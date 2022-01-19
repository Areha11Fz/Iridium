// Sniffer or whatever you like to call it
const proxy = require('udp-proxy')
const dataUtil = require("./dataUtil");
const kcp = require("node-kcp");
const fs = require("fs");
const sqlite3 = require('sqlite3').verbose();
const { WSMessage } = require("./util/classes");

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
    var bufferMsg = Buffer.from(data);

    // didnt know i was also handling handshake here lmao
    if (bufferMsg.byteLength <= 20) { // Handshake
        switch (bufferMsg.readInt32BE(0)) {
            case 0xFF:
                log("Handshake", "Connected"); break;
            case 404:
                log("Handshake", "Disconnected");
                yuankey = undefined
                break;
            default:
                log("UNKNOWN HANDSHAKE", bufferMsg.readInt32BE(0)); break;
        }
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
    var reformatedPacket = await dataUtil.reformatKcpPacket(bufferMsg);
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
                "EntityAiSyncNotify"
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
                                    data: JSON.stringify(data),
                                }
                                global.queryPackets.push(new WSMessage('evt_new_packet', Buffer.from(toWS).toString('base64')));
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
                }
                else if (packetID == parseInt(dataUtil.getProtoNameByPacketID(packetID))) {
                    itsSus++
                    fs.appendFile("./unk/unknown_packets/" + itsSus + "_" + packetID, "unknown", (err) => {
                        if (err)
                            throw err;
                    })
                    return;
                }

                if (packetID == 133) {
                    var proto = await dataUtil.dataToProtobuffer(dataUtil.removeMagic(recv), "GetPlayerTokenRsp")
                    var execFile = require('child_process').execFile;
                    execFile('./yuanshenKey/ConsoleApp2.exe', [proto.secretKeySeed], function (err, data) {
                        if (err) {
                            log("ERROR", err)
                        }
                        log("DEBUG", proto.secretKeySeed.toString())
                        yuankey = Buffer.from(data.toString(), 'hex');
                    });
                }
                if (packetID == 115) {
                    fs.writeFile("./bins/" + dataUtil.getProtoNameByPacketID(packetID) + (num > 0 ? num : "") + ".bin", dataUtil.parsePacketData(recv), (err) => {
                        log("ERROR", err)
                    });
                }
            }
        }
    }

}

module.exports = {
    async execute(port, host) {
        var options = {
            address: '47.90.134.247', // America: 47.90.134.247, Europe: 47.245.143.151
            port: port,
            localaddress: '127.0.0.1',
            localport: port,
        };


        var server = proxy.createServer(options);

        server.on('listening', function (details) {
            log("UDP", `Proxy Listening @ " + ${details.target.address}:${details.target.port}`);
        });

        server.on('bound', function (details) {
            log('UDP', `Proxy bound to ${details.route.address}:${details.route.port}`);
            log('UDP', `Peer bound to ${details.peer.address}:${details.peer.port}`);
        });

        // 'message' is emitted when the server gets a message
        server.on('message', async function (message, sender) {
            doTheWholeThing("CLIENT", message, sender);
        });

        // 'proxyMsg' is emitted when the bound socket gets a message and it's send back to the peer the socket was bound to
        server.on('proxyMsg', async function (message, sender, peer) {
            doTheWholeThing("SERVER", message, sender);
        });
    }
}