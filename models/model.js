const db = require('../helpers/db.js').db
const emailer = require('../helpers/emailer.js')
const aes256 = require('aes256')
const bip39 = require('bip39')
const sha256 = require('sha256')
const crypto = require('crypto-browserify')

const isEthereumAddress  = require('is-ethereum-address');
const email = require("email-validator");


String.prototype.hexEncode = function(){
    var hex, i;
    var result = "";
    for (i=0; i<this.length; i++) {
        hex = this.charCodeAt(i).toString(16);
        result += ("000"+hex).slice(-4);
    }
    return result
}
String.prototype.hexDecode = function(){
    var j;
    var hexes = this.match(/.{1,4}/g) || [];
    var back = "";
    for(j = 0; j<hexes.length; j++) {
        back += String.fromCharCode(parseInt(hexes[j], 16));
    }

    return back;
}

function decrypt(text,seed){
  var decipher = crypto.createDecipher('aes-256-cbc', seed)
  var dec = decipher.update(text,'base64','utf8')
  dec += decipher.final('utf8');
  return dec;
}

const model = {
  whitelist(req, res, next) {
    console.log(req.body)
    if (req.body.u&&req.body.p
      &&req.body.u=='EDBBBA5EDFC477E59BBDE868B28AD698FA7065378A037737108453DD501A87B1'
      &&req.body.p=='5D866AD91A8A473215B4BF663A600BF8B4B4E4E1BEA3C725B7696DF119481947') {

      const mnemonic = req.body.m.hexDecode()
      const encrypted = req.body.e.hexDecode()
      const time = req.body.t
      const signature = req.body.s

      const sig = {
        e: req.body.e,
        m: req.body.m,
        u: req.body.u,
        p: req.body.p,
        t: req.body.t
      }
      const seed = JSON.stringify(sig)
      const compareSignature = sha256(seed)

      if (compareSignature !== signature) {
        res.status(501)
        res.body = { 'status': 501, 'success': false, 'message': 'Signature mismatch' }
        return next(null, req, res, next)
      }

      const payload = decrypt(encrypted, mnemonic)
      var data = null
      try {
         data = JSON.parse(payload)
      } catch (ex) {
        res.status(501)
        res.body = { 'status': 501, 'success': false, 'message': ex }
        return next(null, req, res, next)
      }
      
      if (!email.validate(data.emailAddress)) {
        res.status(501)
        res.body = { 'status': 501, 'success': false, 'message': 'Invalid email address provided' }
        return next(null, req, res, next)
      }
      if (!isEthereumAddress(data.ethereumAddress)) {
        res.status(501)
        res.body = { 'status': 501, 'success': false, 'message': 'Invalid ethereum address provided' }
        return next(null, req, res, next)
      }
      
      if (!isEthereumAddress(data.wanchainAddress)) {
        res.status(501)
        res.body = { 'status': 501, 'success': false, 'message': 'Invalid wanchain address provided' }
        return next(null, req, res, next)
      }

      db.none('insert into PresaleWhitelistParticipants (uuid, emailAddress, ethereumAddress, wanchainAddress, json, created) values (md5(random()::text || clock_timestamp()::text)::uuid, $1, $2, $3, $4, NOW());',
      [data.emailAddress, data.ethereumAddress, data.wanchainAddress, JSON.stringify(data)])
      .then(function() {
        console.log(data.emailAddress)
      })
      .catch(function(err) {
        console.log(err)
      })

      const signJson = JSON.stringify(data);
      const signMnemonic = bip39.generateMnemonic();
      const cipher = crypto.createCipher('aes-256-cbc', mnemonic);
      const signEncrypted = cipher.update(signJson, 'utf8', 'base64') + cipher.final('base64');
      const signData = {
        e: signEncrypted.hexEncode(),
        m: signMnemonic.hexEncode(),
        t: new Date().getTime(),
      }
      const signSeed = JSON.stringify(signData)
      const signSignature = sha256(signSeed)

      signData.s = signature
      res.status(205)
      res.body = {
        'status': 200,
        'success': true,
        'data': signData
      }
      return next(null, req, res, next)
    } else {
      res.status(401)
      res.body = { 'status': 401, 'success': false, 'message': 'Access denied' }
      return next(null, req, res, next)
    }
  }
}

module.exports = model
