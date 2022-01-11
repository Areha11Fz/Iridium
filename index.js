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
const log = (event, data) => console.log(`${new Date()} \t ${event} \t ${data}`);
const http = require('http');
const https = require('https');
const fs = require('fs');
let requestListener = function (req, res) {
    if (req.url === '/favicon.ico') {
        res.writeHead(200, {'Content-Type': 'image/x-icon'} );
        res.end();
        return;
    }


    try {
        res.writeHead(200, { "Content-Type": "text/html" });
        const file = require(path.resolve(__dirname, "../www/") + req.url.split("?")[0]);
        file.execute(req, res);
        if (req.url != "/perf/dataUpload") {
            log("200 OK " + req.url);
        }
    }
    catch (e) {
        res.writeHead(200, { "Content-Type": "text/html" });
        log("404 " + req.url);
        res.end('{"code":0}');
        
    }
}
const httpsOptions = {
    key: fs.readFileSync("./cert/ys.key"),
    cert: fs.readFileSync("./cert/ys.crt")
};
const httpserver = http.createServer(requestListener).listen(80, () => { log('HTTP', 'Running on port 80') });
const httpsserver = https.createServer(httpsOptions, requestListener).listen(443, () => { log('HTTPS', 'Running on port 443') });

const sniffer = require('./backend/sniffer');

sniffer.execute(22101);
sniffer.execute(22102)