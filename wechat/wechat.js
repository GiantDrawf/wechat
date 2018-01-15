'use strict'

const crypto = require('crypto'),
    https = require('https'),
    util = require('util'),
    fs = require('fs'),
    urltil = require('url'),
    parseString = require('xml2js').parseString,
    accessTokenJson = require('./access_token'),
    msg = require('./msg'),
    CryptoGraphy = require('./cryptoGraphy'),
    getTicketUrl = require('../TrainTicket/getTicket');

/**
 * 构建weChat对象
 * @param {JSON} config 配置文件
 */
class WeChat {
    /**
     * WeChat类构造器
     * @param {*} config
     */
    constructor(config) {
        this.config = config;
        this.token = config.token;
        this.appID = config.appID;
        this.appScrect = config.appScrect;
        this.apiDomain = config.apiDomain;
        this.apiURL = config.apiURL;
    }
}
/**
 * 处理 https GET请求的方法
 * @param {String} url 请求地址
 */
WeChat.prototype.requestGet = function (url) {
    return new Promise((resolve, reject) => {
        https.get(url, res => {
            var buffer = [],
                result = '';
            // 监听data事件
            res.on('data', function (data) {
                buffer.push(data);
            });
            //监听数据传输完成事件
            res.on('end', function () {
                result = Buffer.concat(buffer).toString('utf-8');
                //将最后结果返回
                resolve(result);
            });
        }).on('error', err => {
            reject(err);
        });
    });
}

WeChat.prototype.requestGetTicket = function (url) {
    return new Promise((resolve, reject) => {
        var options = {
            hostname: url,
            method: 'GET',
            headers: {
                'Referer': 'https://kyfw.12306.cn/otn/leftTicket/init',
                'Host': 'kyfw.12306.cn'
            }
        }
        var req = https.get(options, res => {
            var buffer = [],
                result = '';
            res.on('data', function (data) {
                buffer.push(data);
            });
            res.on('end', function () {
                result = Buffer.concat(buffer).toString('utf-8');
                resolve(result);
            });
        })
        // 监听错误事件
        .on('error', err => {
            reject(err);
        });
        req.end();
    });
}

/**
 * 用于处理 https Post请求方法
 * @param {String} url  请求地址
 * @param {JSON} data 提交的数据
 */
WeChat.prototype.requestPost = function (url, data) {
    return new Promise((resolve, reject) => {
        //解析 url 地址
        var urlData = urltil.parse(url);
        //设置 https.request  options 传入的参数对象
        var options = {
            //目标主机地址
            hostname: urlData.hostname,
            //目标地址
            path: urlData.path,
            //请求方法
            method: 'POST',
            //头部协议
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(data, 'utf-8')
            }
        };
        var req = https.request(options, res => {
            var buffer = [], result = '';
            //用于监听 data 事件 接收数据
            res.on('data', data => {
                buffer.push(data);
            });
            //用于监听 end 事件 完成数据的接收
            res.on('end', () => {
                result = Buffer.concat(buffer).toString('utf-8');
                resolve(result);
            })
        })
            //监听错误事件
            .on('error', err => {
                console.log(err);
                reject(err);
            });
        //传入数据
        req.write(data);
        req.end();
    });
}

/**
 * 微信接入验证
 * @param {Request} req Request 对象
 * @param {Response} res Response 对象
 */
WeChat.prototype.auth = function (req, res) {
    // 获取微信服务器Get请求的参数 signature、timestamp、nonce、echostr
    var signature = req.query.signature,//微信加密签名
        timestamp = req.query.timestamp,//时间戳
        nonce = req.query.nonce,//随机数
        echostr = req.query.echostr;//随机字符串

    // 将token、timestamp、nonce三个参数进行字典序排序
    var array = [this.token, timestamp, nonce];
    array.sort();

    // 将三个参数字符串拼接成一个字符串进行sha1加密
    var tempStr = array.join('');
    const hashCode = crypto.createHash('sha1'); //创建加密类型
    var resultCode = hashCode.update(tempStr, 'utf8').digest('hex'); //对传入的字符串进行加密

    // 开发者获得加密后的字符串可与signature对比，标识该请求来源于微信
    if (resultCode === signature) {
        console.log('接入微信服务器成功');
        res.send(echostr);
    } else {
        res.send('mismatch');
    }
}

/**
 * 获取微信 access_token
 */
WeChat.prototype.getAccessToken = function () {
    var that = this;
    return new Promise(function (resolve, reject) {
        //获取当前时间
        var currentTime = new Date().getTime();
        //格式化请求地址
        var url = util.format(that.apiURL.accessTokenApi, that.apiDomain, that.appID, that.appScrect);
        //判断 本地存储的 access_token 是否有效
        if (accessTokenJson.access_token === "" || accessTokenJson.expires_time < currentTime) {
            that.requestGet(url).then(function (data) {
                var result = JSON.parse(data);
                if (data.indexOf("errcode") < 0) {
                    accessTokenJson.access_token = result.access_token;
                    accessTokenJson.expires_time = new Date().getTime() + (parseInt(result.expires_in) - 200) * 1000;
                    //更新本地存储的
                    fs.writeFile('./wechat/access_token.json', JSON.stringify(accessTokenJson));
                    //将获取后的 access_token 返回
                    resolve(accessTokenJson.access_token);
                } else {
                    //将错误返回
                    resolve(result);
                }
            });
        } else {
            //将本地存储的 access_token 返回
            resolve(accessTokenJson.access_token);
        }
    });
}

/**
 * 获取12306车票信息
 */
WeChat.prototype.getTicketInfo = function () {
    var that = this;
    return new Promise(function (resolve, reject) {
        // 格式化请求地址
        var url = getTicketUrl.getTicket('2018-02-12', 'BJP', 'CZH');
        console.log(url);
        that.requestGetTicket(url).then(function (data) {
            var result = JSON.parse(data);
            resolve(result);
        })
    })
}

/**
 * 微信消息处理
 * @param {Request} req
 * @param {Response} res
 */
WeChat.prototype.handleMsg = function (req, res) {
    var buffer = [],
        that = this;

    // 实例化微信消息加解密
    var cryptoGraphy = new CryptoGraphy(that.config, req);

    //监听 data 事件 用于接收数据
    req.on('data', function (data) {
        buffer.push(data);
    });

    //监听 end 事件， 用于处理接收完成的数据
    req.on('end', function () {
        var msgXml = Buffer.concat(buffer).toString('utf-8');
        // 解析xml
        parseString(msgXml, { explicitArray: false }, function (err, result) {
            if (!err) {
                result = result.xml;
                //判断消息加解密方式
                if (req.query.encrypt_type == 'aes') {
                    //对加密数据解密
                    result = cryptoGraphy.decryptMsg(result.Encrypt);
                }
                var toUser = result.ToUserName; //接收方微信
                var fromUser = result.FromUserName;//发送仿微信
                var reportMsg = ''; //声明回复消息的变量

                //判断消息类型
                if (result.MsgType.toLowerCase() === "text") {
                    reportMsg = msg.txtMsg(fromUser, toUser, 'Hi!');
                }
                //判断消息加解密方式，如果未加密则使用明文，对明文消息进行加密
                reportMsg = req.query.encrypt_type == 'aes' ? cryptoGraphy.encryptMsg(reportMsg) : reportMsg;
                //返回给微信服务器
                res.send(reportMsg);
            } else {
                console.log(err);
            }
        });
    });
}

/**
 * 暴露供外部访问接口
 */
module.exports = WeChat;