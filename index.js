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

const sniffer = require('./backend/sniffer');
const http_genshin = require('./backend/http_genshin');
const webSocket = require('./webSocket');

webSocket.execute();