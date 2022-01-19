/**
 * @file interface.js
 * @author memetrollsXD
 * @description This file is the main entry point for the Iridium interface.
 */
const http = require('http');
const https = require('https');
const fs = require('fs');
const { log } = require("./util/log");
let requestListener = function (req, res) {
    if (req.url === '/favicon.ico') {
        res.writeHead(200, { 'Content-Type': 'image/x-icon' });
        res.end();
        return;
    }


    try {
        res.writeHead(200, { "Content-Type": "text/html" });
        const file = require(path.resolve(__dirname, "./frontend/") + req.url.split("?")[0]);
        file.execute(req, res);
    }
    catch (e) {
        res.writeHead(200, { "Content-Type": "text/html" });
        log("404 " + req.url);
        res.end('404 Not Found');

    }
}
const httpsOptions = {
    key: fs.readFileSync("./cert/ys.key"),
    cert: fs.readFileSync("./cert/ys.crt")
};
module.exports = {
    execute() {
        https.createServer(httpsOptions, requestListener).listen(1984, () => { log('INTERFACE', 'Running https://localhost:1984') });
    }
}