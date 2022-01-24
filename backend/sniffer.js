// Sniffer or whatever you like to call it
const proxy = require('udp-proxy')
const dataUtil = require("./dataUtil");
const kcp = require("node-kcp");
const fs = require("fs");
const pcapp = require('pcap-parser');
const SQLiteCrud = require('sqlite3-promisify');
const util = require('util');
const execFile = util.promisify(require('child_process').execFile);
const {
	WSMessage
} = require("../util/classes");
const log = (event, data) => console.log(`${new Date()} \t ${event} \t ${data}`);

// const keysDB = new SQLiteCrud('./keys.db');
const packetQueue = [];
const DIR_SERVER = 0;
const DIR_CLIENT = 1;
const PACKET_GetPlayerTokenRsp = dataUtil.getPacketIDByProtoName('GetPlayerTokenRsp');

let packetQueueSize = 0;
let unknownPackets = 0, packetOrderCount = 0;
let initialKey, yuankey;

var serverBound = {};
var clientBound = {};

async function processMHYPacket(data, ip) {
	if(!data) return log('WARNING', "Empty data received.");
	let KCPContextMap;
	let packetSource = (ip.port == 22101 || ip.port == 22102)? DIR_SERVER : DIR_CLIENT;
	if (packetSource == DIR_SERVER) {
		KCPContextMap = serverBound;
	} else {
		KCPContextMap = clientBound;
	}

	if (data.byteLength <= 20) {
		switch (data.readInt32BE(0)) {
			case 0xFF:
				log("Handshake", "Connected");
				break;
			case 404:
				log("Handshake", "Disconnected"); //red
				yuankey = undefined
				break;
			default:
				log("UNKNOWN HANDSHAKE", data.readInt32BE(0));
				break;
		}
		return;
	}	
	
	let peerID = ip.address + '_' + ip.port + '_' + data.readUInt32LE(0).toString(16);
	if(!KCPContextMap[peerID]) {
		KCPContextMap[peerID] = new kcp.KCP(data.readUInt32LE(0), ip);
		log('KCP', 'Instance created: '+ peerID)
	}

	let kcpobj = KCPContextMap[peerID];
	kcpobj.input(await dataUtil.reformatKcpPacket(data))
	kcpobj.update(Date.now())

	let recv = kcpobj.recv();

	if(!recv) return; //log('KCP', 'Recv is empty.'); //red

	let keyBuffer = yuankey || initialKey;
	
	if(!keyBuffer) return log('KCP', 'NO KEY PROVIDED.'); //red

	dataUtil.xorData(recv, keyBuffer);

	// if(recv.length <= 5
	// || recv.readInt16BE(0) != 0x4567
	// || recv.readUInt16BE(recv.byteLength - 2) != 0x89AB)
	// 	return log('KCP', 'The packet signature is invalid.');//red

	let packetID = recv.readUInt16BE(2);
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
    if(ignoredPackets.includes(protoName)) return;
	
	let name = ['SERVER','CLIENT'][packetSource];
	log(`[${name}]`, `Sent packet ${packetID} ${protoName}`);
	//log(await dataUtil.dataToProtobuffer(dataUtil.parsePacketData(recv), packetID));
	if (packetID == +protoName) {
		unknownPackets++
		fs.appendFile("./unk/unknown_packets/" + unknownPackets + "_" + packetID, "unknown", (err) => {
			if (err)
				throw err;
		})
		return;
	}

	if (packetID == PACKET_GetPlayerTokenRsp) {
		var proto = await dataUtil.dataToProtobuffer(dataUtil.removeMagic(recv), "GetPlayerTokenRsp")
		const {stdout, stderr} = await execFile('./yuanshenKey/ConsoleApp2.exe', [proto.secretKeySeed]);
		log("DEBUG", proto.secretKeySeed.toString())
		yuankey = Buffer.from(stdout.toString(), 'hex');
		return;
	}
	// if (packetID == 115) {
	// 	fs.writeFileSync("./bins/" + protoName + (num > 0 ? num : "") + ".bin", dataUtil.parsePacketData(recv), (err) => {
	// 		log("ERROR", err)
	// 	});
	// 	return;
	// }
	if (packetID != parseInt(protoName)) {
		var num = 0;
		while (true) {
			try {
				fs.statSync(`./bins/${protoName}${(num > 0 ? num : "")}.json`);
				fs.statSync(`./bins/bin/${protoName}${(num > 0 ? num : "")}.bin`);
				num++
				continue
			} catch {
				try {
					let data = await dataUtil.dataToProtobuffer(dataUtil.parsePacketData(recv), packetID);
					fs.writeFileSync(`./bins/bin/${protoName}${(num > 0 ? num : "")}.bin`, dataUtil.parsePacketData(recv), (err) => {
						// log(err)
					});
					fs.writeFileSync(`./bins/${protoName}${(num > 0 ? num : "")}.json`, JSON.stringify(data), (err) => {
						// log(err)
					});
					toWS = {
						protoname: protoName,
						data: data
					}
					global.queryPackets.push(new WSMessage('evt_new_packet', JSON.stringify(toWS).toString('base64')));
				} catch (e) {
					log("ERROR", e);
				}
				break;
			}
		}

		packetOrderCount++
		fs.appendFile(`./unk/packet_order/${protoName}_${packetID}_${name}_${packetOrderCount}`, dataUtil.parsePacketData(recv), (err) => {
			// log(err)
		});
	}
}

module.exports = {
	async execute(pcapFile) {
		// let row = await keysDB.get('SELECT * FROM keys WHERE first_bytes=51544');
		initialKey = Buffer.from(require('./key.json'),'base64');
		// console.log(initialKey)
		var parser = pcapp.parse(pcapFile);
		parser.on('packet', function(packet) {
			packetQueue.push(packet)
			packetQueueSize++;
		});
		setInterval(async () => {
			if(!packetQueueSize) return;
			while(packetQueue.length) {
				let packet = packetQueue.shift();
				packetQueueSize--;
				if(packet.data.readInt16LE(12) === 8)
					packet.data = packet.data.slice(14);
				let udp = dataUtil.read_pcap_udp_header(packet.data);
				let ip = dataUtil.read_pcap_ipv4_header(packet.data);
				if(udp.port_src !== 22101
				&& udp.port_src !== 22102
				&& udp.port_dst !== 22101
				&& udp.port_dst !== 22102) continue;
				// console.log(read);
				await processMHYPacket(packet.data.slice(28), {
					address: ip.src_addr,
					port: udp.port_src
				});
			}
		}, 100)
		
		parser.on('end', async () => {
			console.log('Parse finished.')
		});
		// var options = {
		//     address: '47.90.134.247', // America: 47.90.134.247, Europe: 47.245.143.151
		//     port: port,
		//     localaddress: '127.0.0.1',
		//     localport: port,
		// };

		// var server = proxy.createServer(options);

		// server.on('listening', function (details) {
		//     log("UDP", `Proxy Listening @ " + ${details.target.address}:${details.target.port}`);
		// });

		// server.on('bound', function (details) {
		//     log('UDP', `Proxy bound to ${details.route.address}:${details.route.port}`);
		//     log('UDP', `Peer bound to ${details.peer.address}:${details.peer.port}`);
		// });

		// // 'message' is emitted when the server gets a message
		// server.on('message', async function (message, sender) {
		//     processMHYPacket("CLIENT", message, sender);
		// });

		// // 'proxyMsg' is emitted when the bound socket gets a message and it's send back to the peer the socket was bound to
		// server.on('proxyMsg', async function (message, sender, peer) {
		//     processMHYPacket("SERVER", message, sender);
		// });
	}
}