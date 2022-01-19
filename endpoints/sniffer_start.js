const fs = require('fs');
const {log} = require('../util/log');
const {WSMessage} = require('../util/classes');
const sniffer = require('../backend/sniffer');

async function execute(id, data) {
    const dataObj = {
        status: "OK"
    }
    log("SERVER", `${id}_rsp`, JSON.stringify(dataObj));
    sniffer.execute(22102);
    return new WSMessage(`${id}_rsp`, dataObj).parse(); // Echo back data given
}

module.exports = {execute: execute}