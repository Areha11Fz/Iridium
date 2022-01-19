const { WSMessage } = require('./util/classes');
const { log } = require('./util/log');
function webSocket() {
    var WebSocketServer = require('ws').Server,
        wss = new WebSocketServer({ port: 40510 })

    wss.on('connection', function (ws) {
        ws.send(1)
        ws.on('message', function (message) {
            const msg = JSON.parse(message);
            try {
                log("CLIENT", `[${msg.cmd}] ${msg.data}`);
                const handler = require(`./endpoints/${msg.cmd}.js`).execute(msg.cmd, msg.data).then(data => {
                    ws.send(data);
                });
            } catch (e) {
                log("ERROR", `${msg.cmd} event not handled`);
                console.log(e);
            }
        })
        setInterval(() => {
            // check if there are children in global.queryPackets
            if (global.queryPackets.length > 0) {
                global.queryPackets.forEach(child => {
                    ws.send(child.parse());
                });
                global.queryPackets = [];
            }
        }, 500);
    })
}
module.exports = { execute: webSocket }