/**
 * @file http_genshin.js
 * @author memetrollsXD
 * @description This file is the main entry point for the HTTP server.
 */
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const {log} = require("../util/log");
let requestListener = function (req, res) {
    if (req.url === '/favicon.ico') {
        res.writeHead(200, {'Content-Type': 'image/x-icon'} );
        res.end();
        return;
    }


    try {
        res.writeHead(200, { "Content-Type": "text/html" });
        const file = require(path.resolve(__dirname, "../www/") + req.url.split("?")[0]);
        log('aaaa')
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
module.exports = {
    execute() {
        http.createServer(requestListener).listen(80, () => { log('HTTP', 'Running on port 80') });
        https.createServer(httpsOptions, requestListener).listen(443, () => { log('HTTPS', 'Running on port 443') });
    }
}