const axios = require('axios');
const yaml = require('js-yaml');
const options = yaml.load(require('fs').readFileSync('./config.yml', 'utf8'));
module.exports = {
    async execute(req, res) {
        await axios.get(`http://memetrolls.net:9124/query_cur_region?key=${options.apikey}`).then(response => {
            res.end(response.data);
        });
    }
}