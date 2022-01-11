module.exports = {
    execute(req, res){
        var ret = {
            "retcode":0,
            "message":"OK",
            "data":{
                "list":[{
                    "ann_id":2700,
                    "title":"<b>Welcome!</b>",
                    "subtitle":"<b>CrepePS</b>",
                    "banner":"placeholder.png",
                    "content":"Welcome.",
                    "lang":"es-es"
                }],
                "total":1
            }
        }
        res.end(JSON.stringify(ret));
    }
}