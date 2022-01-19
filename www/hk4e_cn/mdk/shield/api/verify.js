
module.exports = {
    execute(req, res) {
        var ret = {
            "retcode": 0,
            "message": "OK",
            "data": {
                "account": {
                    "uid": "420",
                    "name": "",
                    "email": "If you see this, you've messed up. Start sniffer after login",
                    "mobile": "",
                    "is_email_verify": "0",
                    "realname": "",
                    "identity_card": "",
                    "token": "token", // Bueno, se supone que aqui debe de haber un token :+1:
                    "safe_mobile": "",
                    "facebook_name": "",
                    "google_name": "",
                    "twitter_name": "",
                    "game_center_name": "",
                    "apple_name": "",
                    "sony_name": "",
                    "tap_name": "",
                    "country": "MX",
                    "reactivate_ticket": "",
                    "area_code": "**"
                },
                "device_grant_required": false,
                "safe_moblie_required": false,
                "realperson_required": false
            }
        }
        ret.data.account.email = global.accountName;
        res.end(JSON.stringify(ret));
    }
}