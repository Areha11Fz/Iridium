// Sniffer or whatever you like to call it
const proxy = require('udp-proxy')
const dataUtil = require("./dataUtil");
const kcp = require("node-kcp");
const fs = require("fs");
const sqlite3 = require('sqlite3').verbose();
const util = require('util');
const execFile = util.promisify(require('child_process').execFile);
const {
	WSMessage
} = require("../util/classes");

const packets = [];

const log = (event, data) => console.log(`${new Date()} \t ${event} \t ${data}`);

// sussy
var itsSus, packetOrderCount = 0;
var initialKey, yuankey = undefined;

let db = new sqlite3.Database('./keys.db', (error) => {
	if (error) {
		throw error; // wooo
	}

	db.get('SELECT * FROM keys WHERE first_bytes=51544', async (err, row) => { // SQLite Database
		initialKey = Buffer.from(row.key_buffer)
	});
});

var clientClients = {};
var serverClients = {};

async function doTheWholeThing(name, data, rinfo) {
	var client;
	if (name == "SERVER") {
		client = serverClients
	} else {
		client = clientClients
	}

	var k = rinfo.address + '_' + rinfo.port + '_' + data.readUInt32LE(0).toString(16);
	// console.log(k);
	data = Buffer.from(data);

	// didnt know i was also handling handshake here lmao
	
	if (data.byteLength <= 20) { // Handshake
		switch (data.readInt32BE(0)) {
			case 0xFF:
				log("Handshake", "Connected");
				break;
			case 404:
				log("Handshake", "Disconnected");
				yuankey = undefined
				break;
			default:
				log("UNKNOWN HANDSHAKE", data.readInt32BE(0));
				break;
		}
		console.log(k);
		return
	}

	if (undefined === client[k]) {
		var context = {
			address: rinfo.address,
			port: rinfo.port
		};
		var kcpobj = new kcp.KCP(data.readUInt32LE(0), context);
		//kcpobj.nodelay(0, interval, 0, 0);
		//kcpobj.output(output);
		client[k] = kcpobj;
	}


	var kcpobj = client[k]
	var reformatedPacket = await dataUtil.reformatKcpPacket(data);


	kcpobj.input(reformatedPacket)
	kcpobj.update(Date.now())

	var recv = kcpobj.recv();
	if (recv) {
		var keyBuffer = yuankey == undefined ? initialKey : yuankey;
			dataUtil.xorData(recv, keyBuffer);

		// log("[RECV " + name + "] ") //+ recv.toString('hex'));

		if (recv.length > 5 && recv.readInt16BE(0) == 0x4567 && recv.readUInt16BE(recv.byteLength - 2) == 0x89AB) {
			var packetID = recv.readUInt16BE(2); // Packet ID
			let ignoredPackets = [ //! Forward to frontend
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
                
                "TakeAchievementRewardRsp"
            ]
			if (!ignoredPackets.includes(dataUtil.getProtoNameByPacketID(packetID))) {
				log(`[${name}] Got packet ${packetID} ${dataUtil.getProtoNameByPacketID(packetID)}`); // Debug
				var dataBuffer = await dataUtil.dataToProtobuffer(dataUtil.parsePacketData(recv), packetID);
				//log(dataBuffer);
				if (packetID != parseInt(dataUtil.getProtoNameByPacketID(packetID))) {
					var num = 0;
					while (true) {
						try {
							fs.statSync(`./bins/${dataUtil.getProtoNameByPacketID(packetID)}${(num > 0 ? num : "")}.json`);
							fs.statSync(`./bins/bin/${dataUtil.getProtoNameByPacketID(packetID)}${(num > 0 ? num : "")}.bin`);
							num++
							continue
						} catch {
							try {
								let data = await dataUtil.dataToProtobuffer(dataUtil.parsePacketData(recv), packetID);
								fs.writeFileSync(`./bins/bin/${dataUtil.getProtoNameByPacketID(packetID)}${(num > 0 ? num : "")}.bin`, dataUtil.parsePacketData(recv), (err) => {
									// log(err)
								});
								fs.writeFileSync(`./bins/${dataUtil.getProtoNameByPacketID(packetID)}${(num > 0 ? num : "")}.json`, JSON.stringify(data), (err) => {
									// log(err)
								});
								toWS = {
									protoname: dataUtil.getProtoNameByPacketID(packetID),
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
					fs.appendFile(`./unk/packet_order/${dataUtil.getProtoNameByPacketID(packetID)}_${packetID}_${name}_${packetOrderCount}`, dataUtil.parsePacketData(recv), (err) => {
						// log(err)
					});
				} else if (packetID == parseInt(dataUtil.getProtoNameByPacketID(packetID))) {
					itsSus++
					fs.appendFile("./unk/unknown_packets/" + itsSus + "_" + packetID, "unknown", (err) => {
						if (err)
							throw err;
					})
					return;
				}

				if (packetID == 133) {
					var proto = await dataUtil.dataToProtobuffer(dataUtil.removeMagic(recv), "GetPlayerTokenRsp")
					const {stdout, stderr} = await execFile('./yuanshenKey/ConsoleApp2.exe', [proto.secretKeySeed]);
					if (stderr) {
						log("ERROR", stderr)
					}
					log("DEBUG", proto.secretKeySeed.toString())
					log("DEBUG", stdout.toString())
					yuankey = Buffer.from(stdout.toString(), 'hex');
				}
				if (packetID == 115) {
					fs.writeFileSync("./bins/" + dataUtil.getProtoNameByPacketID(packetID) + (num > 0 ? num : "") + ".bin", dataUtil.parsePacketData(recv), (err) => {
						log("ERROR", err)
					});
				}
			}
		}
	}

}

module.exports = {
	async execute(port, host) {
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
		//     doTheWholeThing("CLIENT", message, sender);
		// });

		// // 'proxyMsg' is emitted when the bound socket gets a message and it's send back to the peer the socket was bound to
		// server.on('proxyMsg', async function (message, sender, peer) {
		//     doTheWholeThing("SERVER", message, sender);
		// });
		var pcapp = require('pcap-parser');

		function read_pcap_ipv4_header(buffer, offset = 0) {
			const ip_version_number = parseInt(buffer[offset].toString(16)[0], 16);
			offset += 0; // not a typo
			const ihl = parseInt(buffer[offset].toString(16)[1], 16);
			offset += 1;
			const service_type = buffer[offset];
			offset += 1;
			const total_length = buffer.readUInt16LE(offset);
			offset += 16 / 8;
			const id = buffer.readUInt16LE(offset);
			offset += 16 / 8;
			const flags = parseInt(buffer[offset].toString(16)[0], 16);
			offset += 0; // not a typo
			const fragment_offset = ((buffer[offset] & 0x0F) << 8) | (buffer[offset + 1] & 0xff); // needs to be fixed
			offset += 2;
			const time_to_live = buffer[offset];
			offset += 1;
			const protocol = buffer[offset];
			offset += 1;
			const header_checksum = buffer.readUInt16LE(offset);
			offset += 16 / 8;
			const src_addr = buffer.slice(offset, offset + (32 / 8)).toString('hex').match(/../g).map((byte) => parseInt(byte, 16)).join('.');
			offset += 32 / 8;
			const dst_addr = buffer.slice(offset, offset + (32 / 8)).toString('hex').match(/../g).map((byte) => parseInt(byte, 16)).join('.');
			offset += 32 / 8;
			const ipv4_header = {
				ip_version_number,
				ihl,
				service_type,
				total_length,
				id,
				flags,
				fragment_offset,
				time_to_live,
				protocol,
				header_checksum,
				src_addr,
				dst_addr
			};
			return {
				ipv4_header,
				offset
			};
		}

		function read_pcap_udp_header(buffer, offset = 20) {
			const port_src = buffer.readUInt16BE(offset);
			offset += 16 / 8;
			const port_dst = buffer.readUInt16BE(offset);
			offset += 16 / 8;
			const length = buffer.readUInt16BE(offset);
			offset += 16 / 8;
			const checksum = buffer.readUInt16BE(offset);
			offset += 16 / 8;
			const udp_header = {
				port_src,
				port_dst,
				length,
				checksum
			};
			return {
				udp_header,
				offset
			};
		}
		setTimeout(() => {
			var parser = pcapp.parse('./data/pcap.pcap');
			parser.on('packet', function(packet) {
				packets.push(packet)
			});
		}, 500)
		setTimeout(async () => {
			for (var i = 0; i < packets.length; i++) {
				let packet = packets[i];
				let udp = read_pcap_udp_header(packet.data);
				let ip = read_pcap_ipv4_header(packet.data);
				// console.log(read);
				let cl = udp.udp_header.port_src == 22101 ? "SERVER" : "CLIENT";
				await doTheWholeThing(cl, packet.data.slice(28), {
					address: ip.ipv4_header.src_addr,
					port: udp.udp_header.port_src
				});
			}
		}, 1000)

	}
}