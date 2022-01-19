/**
 * @function log Logs a message to the console
 * @param {string} event 
 * @param {*} data 
 */
const log = (event, data) => console.log(`${new Date()} \t ${event} \t ${data}`);
module.exports = { log: log }