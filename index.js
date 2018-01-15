const express = require('express'),
       config = require('./config'),
       fs = require('fs'),
       //wechatAPI = require('wechat-api'),
       wechat = require('./wechat/wechat');

var app = express();
    wechatApp = new wechat(config);


app.get('/', function(req, res){
    wechatApp.auth(req, res);
});

app.post('/', function(req, res){
    wechatApp.handleMsg(req, res);
});

app.get('/getAccessToken', (req, res) => {
    wechatApp.getAccessToken().then( data => {
        res.send(data);
    });
});

var port = process.env.PORT || '3000';
app.listen(port, function(){
    console.log('Listen to localhost:' + port);
});