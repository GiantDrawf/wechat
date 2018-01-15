'use strict'

module.exports.getTicket = function(trainData, fromStation, toStation){
    let getTicketUrl = `https://kyfw.12306.cn/otn/leftTicket/queryZ?leftTicketDTO.train_date=${trainData}&leftTicketDTO.from_station=${fromStation}&leftTicketDTO.to_station=${toStation}&purpose_codes=ADULT`;
    return getTicketUrl;
}