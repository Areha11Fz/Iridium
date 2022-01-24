// Sniffer or whatever you like to call it
const proxy = require('udp-proxy')
const dataUtil = require("./dataUtil");
const kcp = require("node-kcp");
const fs = require("fs");
const pcapp = require('pcap-parser');
const SQLiteCrud = require('sqlite3-promisify');
const DelimiterStream = require('delimiter-stream');
const GOOD = require('../mappings/index.js');
const util = require('util');
const execFile = util.promisify(require('child_process').execFile);
const udpPacket = require('udp-packet');
const ipPacket = require('ip-packet')
const {
	WSMessage
} = require("../util/classes");
const log = (event, data) => console.log(`${new Date()} \t ${event} \t ${data}`);
let Session = {
	//filename
	//proxy
}


// const keysDB = new SQLiteCrud('./keys.db');
const packetQueue = [];
const DIR_SERVER = 0;
const DIR_CLIENT = 1;
const GCAP_DELIM = '█▄█\n';
const GCAP_DIR = './data'
const PACKET_GetPlayerTokenRsp = dataUtil.getPacketIDByProtoName('GetPlayerTokenRsp');

let packetQueueSize = 0;
let unknownPackets = 0,
	packetOrderCount = 0;
let initialKey = Buffer.from(require('./key.json'), 'base64');
let yuankey;

var serverBound = {};
var clientBound = {};

async function processMHYPacket(packet) {
	let {
		crypt,
		uncrypt,
		ip
	} = packet;
	if (uncrypt) return uncrypt;
	if (!crypt) return log('WARNING', "Empty data received.");
	let KCPContextMap;
	let packetSource = (ip.port == 22101 || ip.port == 22102) ? DIR_SERVER : DIR_CLIENT;
	if (packetSource == DIR_SERVER) {
		KCPContextMap = serverBound;
	} else {
		KCPContextMap = clientBound;
	}

	if (crypt.byteLength <= 20) {
		switch (crypt.readInt32BE(0)) {
			case 0xFF:
				log("Handshake", "Connected");
				break;
			case 404:
				log("Handshake", "Disconnected"); //red
				yuankey = undefined
				break;
			default:
				log("UNKNOWN HANDSHAKE", crypt.readInt32BE(0));
				break;
		}
		return;
	}

	let peerID = ip.address + '_' + ip.port + '_' + crypt.readUInt32LE(0).toString(16);
	if (!KCPContextMap[peerID]) {
		KCPContextMap[peerID] = new kcp.KCP(crypt.readUInt32LE(0), ip);
		log('KCP', 'Instance created: ' + peerID)
	}

	let kcpobj = KCPContextMap[peerID];
	kcpobj.input(await dataUtil.reformatKcpPacket(crypt))
	kcpobj.update(Date.now())

	let recv = kcpobj.recv();

	if (!recv) return; //log('KCP', 'Recv is empty.'); //red

	let keyBuffer = yuankey || initialKey;

	if (!keyBuffer) return log('KCP', 'NO KEY PROVIDED.'); //red

	dataUtil.xorData(recv, keyBuffer);

	let packetID = recv.readUInt16BE(2);
	if (packetID == PACKET_GetPlayerTokenRsp) {
		var proto = await dataUtil.dataToProtobuffer(dataUtil.removeMagic(recv), "GetPlayerTokenRsp")
		const {
			stdout,
			stderr
		} = await execFile('./yuanshenKey/ConsoleApp2.exe', [proto.secretKeySeed]);
		log("DEBUG", proto.secretKeySeed.toString())
		yuankey = Buffer.from(stdout.toString(), 'hex');
		return recv;
	}

	return recv;
}

async function decodePacketProto(packet, ip) {
	let packetID = packet.readUInt16BE(2);
	let protoName = dataUtil.getProtoNameByPacketID(packetID);
	let ignoredPackets = [
		"QueryPathReq",
		"PingReq",
		"PingRsp",
		"UnionCmdNotify",
		"EvtAiSyncCombatThreatInfoNotify",
		"WorldPlayerRTTNotify",
		"QueryPathRsp",
		"EvtAiSyncSkillCdNotify",
		"SetEntityClientDataNotify",
		"ObstacleModifyNotify",
		"ClientReportNotify",
		"ClientAbilityInitFinishNotify",
		"EntityConfigHashNotify",
		"MonsterAIConfigHashNotify",
		"EntityAiSyncNotify",
		//currently broken packets
		"TakeAchievementRewardRsp",
		"ActivityPlayOpenAnimNotify",
		"FurnitureCurModuleArrangeCountNotify",
		"HomeAvatarTalkFinishInfoNotify",
		"GroupLinkAllNotify",
		"UnlockedFurnitureSuiteDataNotify",
		"HomeAvatarRewardEventNotify",
		"H5ActivityIdsNotify",
		"HomePriorCheckNotify",
		"HomePlantInfoNotify",
		"HomeResourceNotify",
		"HomeAvatarAllFinishRewardNotify",
		"HomeBasicInfoNotify",
		"FurnitureMakeRsp"
	]
	if (ignoredPackets.includes(protoName)) return;

	let packetSource = (ip.port == 22101 || ip.port == 22102) ? DIR_SERVER : DIR_CLIENT;
	let name = ['SERVER', 'CLIENT'][packetSource];
	log(`[${name}]`, `Sent packet ${packetID} ${protoName}`);
	if (packetID != parseInt(protoName)) {
		let object = await dataUtil.dataToProtobuffer(dataUtil.parsePacketData(packet), packetID);
		return {
			packetID,
			protoName,
			object: object,
		}
	}
	if (packetID == protoName) {
		return {
			packetID,
			protoName
		}
	}
}

function joinBuffers(buffers, delimiter = ' ') {
  let d = Buffer.from(delimiter);
  return buffers.reduce((prev, b) => Buffer.concat([prev, d, b]));
}

module.exports = {
	async execute() {
		async function loop () {
			if (!packetQueueSize) return setImmediate(loop);
			let decryptedDatagram;
			let packetObject;
			while (packetQueue.length) {
				let packet = packetQueue.shift();
				packetQueueSize--;

				if (packet.ip.port !== 22101 &&
					packet.ip.port !== 22102 &&
					packet.ip.port_dst !== 22101 &&
					packet.ip.port_dst !== 22102) continue;

				decryptedDatagram = await processMHYPacket(packet);
				if (!decryptedDatagram) continue;
				// console.log(decryptedDatagram);
				if (Session.datagrams) {
					let datagram;
					if(packet.ip.port === 22101 || packet.ip.port === 22102) {
						datagram = Buffer.concat([Buffer.from([0]), decryptedDatagram])
					}else{
						datagram = Buffer.concat([Buffer.from([1]), decryptedDatagram])
					}
					Session.datagrams.push(datagram);
				};
				packetObject = await decodePacketProto(decryptedDatagram, packet.ip);
				// console.log(JSON.stringify(packetObject));
				if (packetObject)
					global.queryPackets.push(new WSMessage('evt_new_packet', JSON.stringify(packetObject).toString('base64')));
			}
			if (Session.fileHandle && Session.datagrams && Session.datagrams.length > 0) {
				await Session.fileHandle.appendFile(Buffer.concat([joinBuffers(Session.datagrams, GCAP_DELIM), Buffer.from(GCAP_DELIM)]))
				Session.datagrams = [];
			}
			setImmediate(loop);
		}
		loop();
	},
	async pcap(pcapFile) {
		var parser = pcapp.parse(pcapFile);
		parser.on('packet', packet => {
			if (packet.data.readInt16LE(12) === 8)
				packet.data = packet.data.slice(14);
			let udp = dataUtil.read_pcap_udp_header(packet.data);
			let ip = dataUtil.read_pcap_ipv4_header(packet.data);

			packetQueue.push({
				crypt: packet.data.slice(28),
				ip: {
					address: ip.src_addr,
					address_dst: ip.dst_addr,
					port: udp.port_src,
					port_dst: udp.port_dst
				}
			})
			packetQueueSize++;
		});

		parser.on('end', async () => {
			console.log('Parse finished.')
		});
	},
	async gcap(gcapFile) {
		var fs = require('fs');
		// var StringDecoder = require('string_decoder').StringDecoder;
		// var decoder = new StringDecoder('utf8');

		var linestream = new DelimiterStream({
			delimiter: GCAP_DELIM
		});

		var input = fs.createReadStream(gcapFile);

		// file = file.split(GCAP_DELIM);
		linestream.on('data', packet => {
			// console.log(packet)
			ip = {};
			if (packet.readInt8(0) == 1) {
				ip.port_dst = 22101
				ip.port = null
			}else{
				ip.port = 22101
				ip.port_dst = null
			}
			packetQueue.push({
				uncrypt: packet.slice(1),
				ip
			})
			packetQueueSize++;
		});
		input.pipe(linestream);
	},
	async startProxySession(filename) {
		if (!Session.filename) Session.filename = new Date().toISOString().replace('T', '_').replace(/:/g, '-').split('.')[0] + '.gcap';
		Session.filename = GCAP_DIR + '/' + Session.filename;

		Session.fileHandle = await fs.promises.open(Session.filename, 'w');
		Session.datagrams = [];
		let opt = {
			address: '47.90.134.247', // America: 47.90.134.247, Europe: 47.245.143.151
			port: 22101,
			localaddress: '127.0.0.1',
			localport: 22101,
		}
		Session.proxy = proxy.createServer(opt);

		Session.proxy.on('listening', (details) => {
			log("UDP", `Proxy Listening @ ${details.target.address}:${details.target.port}`);
		});

		Session.proxy.on('bound', (details) => {
			log('UDP', `Proxy bound to ${details.route.address}:${details.route.port}`);
			log('UDP', `Peer bound to ${details.peer.address}:${details.peer.port}`);
		});

		// 'message' is emitted when the server gets a message
		Session.proxy.on('message', (packet, ip) => {
			ip.address_dst = opt.address;
			ip.port_dst = opt.port;
			packetQueue.push({
				crypt: packet,
				ip: ip
			})
			packetQueueSize++;
		});

		// 'proxyMsg' is emitted when the bound socket gets a message and it's send back to the peer the socket was bound to
		Session.proxy.on('proxyMsg', (packet, ip, peer) => {
			ip.address_dst = peer.address;
			ip.port_dst = peer.port;
			packetQueue.push({
				crypt: packet,
				ip: ip
			})
			packetQueueSize++;
		});
	},
	async stopProxySession() {
		if (Session.proxy) Session.proxy.close();
		if (Session.fileHandle) Session.fileHandle.close();
		Session = {};
	}
}