/**
 * @file index.js
 * @author memetrollsXD
*/

/*
For more clarification:
1. Start Genshin
2. Login to ur acc
3. Open UDP Server + Fiddler
4. Profit
*/

const fs = require('fs');
 dir = './tmp/but/then/nested';



global.queryPackets = [];

const http_genshin = require('./backend/http_genshin');
const webSocket = require('./webSocket');
const interface = require('./interface');
const sniffer = require('./backend/sniffer');

webSocket.execute();
http_genshin.execute();
interface.execute();
sniffer.execute(22102);

if (!fs.existsSync('unk/unknown_packets')){
    fs.mkdirSync('unk/unknown_packets', { recursive: true });
}
if (!fs.existsSync('bins/bin')){
    fs.mkdirSync('bins/bin', { recursive: true });
}