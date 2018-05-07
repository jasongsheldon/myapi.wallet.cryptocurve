const { createDecipheriv, createHash } = require('crypto');
const { fromPrivateKey } = require('ethereumjs-wallet');


const { sha3, isValidPrivate } = require('ethereumjs-util');

const db = require('../helpers/db.js').db
const emailer = require('../helpers/emailer.js')
const aes256 = require('aes256')
const bip39 = require('bip39')
const sha256 = require('sha256')
const jwt = require('jwt-simple')
const crypto = require('crypto-browserify')
const isEthereumAddress  = require('is-ethereum-address')
const email = require("email-validator")



const emailHTML = "<!DOCTYPE html PUBLIC ' -//W3C//DTD XHTML 1.0 Transitional//EN' 'http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd'><html xmlns='http://www.w3.org/1999/xhtml'>  <head>    <title>CryptoCurve</title>    <meta http-equiv='Content-Type' content='text/html; charset=utf-8'>    <meta name='viewport' content='width=device-width'>  </head>  <body style='padding:0px;margin:0px;'>    <table style='height: 100%; width: 100%; background-color: #f1f1f2;' align='center'>      <tbody>        <tr>          <td valign='top' style='padding-top:30px;padding-bottom:30px;background-color:#f1f1f2;width:100%;height:100%;'>            <!--[if (gte mso 9)|(IE)]><table style='width:600px' width='600' align='center' cellpadding='0' cellspacing='0' border='0'><tr><td><![endif]-->            <table align='center' border='0' cellpadding='0' cellspacing='0' style='max-width:600px;box-sizing:border-box;width:100%;'>              <tbody>                <tr>                  <td valign='top' align='center' style='background-color:#ffffff;text-align:center;'>                    <!--[if (gte mso 9)|(IE)]><table width='100%' align='center' cellpadding='0' cellspacing='0' border='0'><tr><td><![endif]-->                    <table border='0' cellspacing='0' cellpadding='0' style='background-color:#000000;color:#ffffff'>                      <tbody>                        <tr>                          <td style='text-align:center;background-color:#000000;color:#ffffff;font-weight:bold;font-size:25px'>                            <img style='max-width:600px;width:100%;font-family:Helvetica,Arial,sans-serif;font-size:25px;' width='600' alt='CryptoCurve' src='http://www.eventcloud.co/img/cryptocurve-mail-header.jpg'>                          </td>                        </tr>                      </tbody>                    </table>                    <!--[if (gte mso 9)|(IE)]></td></tr></table><![endif]-->                  </td>                </tr>                <tr>                  <td valign='top' style='background-color: #ffffff'>                    <!--[if (gte mso 9)|(IE)]><table width='100%' align='center' cellpadding='0' cellspacing='0' border='0'><tr><td><![endif]-->                    <table border='0' cellspacing='0' cellpadding='20' style='border-collapse:collapse;width:100%'>                      <tbody>                        <tr>                          <td valign='top' style='font-family:Helvetica,Arial,sans-serif;font-size:13px;color:#2b3c4f;padding-left:20px;padding-right:20px;'>                            <p style='margin:0px;padding:0px;'>                              <span style='font-family:Helvetica,Arial,sans-serif;font-size:13px;color:#2b3c4f'>                                <strong>                                  Awesome!                                </strong>                              </span>                            </p>                            <br/>                            <p style='margin:0px;padding:0px;'>                              <span style='font-family:Helvetica,Arial,sans-serif;font-size:13px;color:#2b3c4f'>                                Thank you for joining the CryptoCurve whitelist.                                <br/><br/>                                We will keep in contact with you via your submitted email address:                                <br/><br/>                                <strong>{{ email }}</strong>                                <br/><br/>                                All you need to do, is send Eth to the address below:                                <br/>                              </span>                            </p>                            <p style='padding-top:20px;padding-bottom:20px;margin-top:30px;margin-bottom:30px;text-align:center; border:1px solid #2b3c4f'>                              <span style='font-family:Helvetica,Arial,sans-serif;font-size:20px;color:#2b3c4f;font-weight:bold;text-align:center;'>                                {{code}}                              </span>                            </p>                            <p style='margin:0px;padding:0px;'>                              <span style='font-family:Helvetica,Arial,sans-serif;font-size:13px;color:#2b3c4f'>                                Enjoy,<br/>                                <strong>The CryptoCurve Team</strong>                              </span>                            </p>                          </td>                        </tr>                      </tbody>                    </table>                    <!--[if (gte mso 9)|(IE)]></td></tr></table><![endif]-->                  </td>                </tr>                <tr>                  <td valign='top' align='center' style='background-color:#000000;'>                    <!--[if (gte mso 9)|(IE)]><table width='100%' align='center' cellpadding='0' cellspacing='0' border='0'><tr><td valign='top'><![endif]-->                    <table border='0' cellpadding='0' cellspacing='0' align='center' style='margin:0 auto; padding-top:10px'>                      <tbody>                        <tr>                          <td>                            <!--[if mso]><table align='center' border='0' cellspacing='0' cellpadding='0'><tr><td align='center' valign='top'><![endif]-->                            <table align='left' border='0' cellpadding='0' cellspacing='0'>                              <tbody>                                <tr>                                  <td align='center' valign='middle' style='padding-top:5px;padding-bottom:5px;padding-left:5px;padding-right:5px'>                                    <span style='font-family:Helvetica,Arial,sans-serif;font-size:12px;color:#ffffff'>                                      <a href='#' style='font-family:Helvetica,Arial,sans-serif;font-size:12px;color:#ffffff;text-decoration: none'>                                        cryptocurve.io                                      </a>                                    </span>                                  </td>                                </tr>                              </tbody>                            </table>                            <!--[if mso]></td><td align='center' valign='top'><![endif]-->                            <table align='left' border='0' cellpadding='0' cellspacing='0'>                              <tbody>                                <tr>                                  <td align='center' valign='middle' style='padding-top:5px;padding-bottom:5px;padding-left:5px;padding-right:5px'>                                    <span style='font-family:Helvetica,Arial,sans-serif;font-size:12px;color:#ffffff'>                                      <a href='#' style='font-family:Helvetica,Arial,sans-serif;font-size:12px;color:#ffffff;text-decoration: none'>                                        cryptocurve.network                                      </a>                                    </span>                                  </td>                                </tr>                              </tbody>                            </table>                            <!--[if mso]></td><td align='center' valign='top'><![endif]-->                            <table align='left' border='0' cellpadding='0' cellspacing='0'>                              <tbody>                                <tr>                                  <td align='center' valign='middle' style='padding-top:5px;padding-bottom:5px;padding-left:5px;padding-right:5px'>                                    <span style='font-family:Helvetica,Arial,sans-serif;font-size:12px;color:#ffffff'>                                      <a href='#' style='font-family:Helvetica,Arial,sans-serif;font-size:12px;color:#ffffff;text-decoration: none'>                                        Our Team                                      </a>                                    </span>                                  </td>                                </tr>                              </tbody>                            </table>                            <!--[if mso]></td></tr></table><![endif]-->                          </td>                        </tr>                      </tbody>                    </table>                    <!--[if (gte mso 9)|(IE)]></td></tr></table><![endif]-->                  </td>                </tr>                <tr>                  <td valign='top' align='center' style='background-color:#000000;'>                    <!--[if (gte mso 9)|(IE)]><table width='100%' align='center' cellpadding='0' cellspacing='0' border='0'><tr><td valign='top'><![endif]-->                    <table border='0' cellpadding='0' cellspacing='0' align='center' style='margin:0 auto'>                      <tbody>                        <tr>                          <td>                            <!--[if mso]><table align='center' border='0' cellspacing='0' cellpadding='0'><tr><td align='center' valign='top'><![endif]-->                            <table align='left' border='0' cellpadding='0' cellspacing='0'>                              <tbody>                                <tr>                                  <td align='center' valign='middle' style='padding-top:5px;padding-bottom:5px;padding-left:5px;padding-right:5px'>                                    <a href='https://www.facebook.com/CryptoCurve/'>                                      <img src='http://www.eventcloud.co/img/cc-facebook.jpg' style='width:30px;height:30px;font-size:12px;color:#333333;border:none;border-width:0px;border-style:none;' alt='Facebook' width='30' height='30'>                                    </a>                                  </td>                                </tr>                              </tbody>                            </table>                            <!--[if mso]></td><td align='center' valign='top'><![endif]-->                            <table align='left' border='0' cellpadding='0' cellspacing='0'>                              <tbody>                                <tr>                                  <td align='center' valign='middle' style='padding-top:5px;padding-bottom:5px;padding-left:5px;padding-right:5px'>                                    <a href='https://twitter.com/crypto_curve'>                                      <img src='http://www.eventcloud.co/img/cc-twitter.jpg' style='width:30px;height:30px;font-size:12px;color:#333333;border:none;border-width:0px;border-style:none;' alt='Twitter' width='30' height='30'>                                    </a>                                  </td>                                </tr>                              </tbody>                            </table>                            <!--[if mso]></td><td align='center' valign='top'><![endif]-->                            <table align='left' border='0' cellpadding='0' cellspacing='0'>                              <tbody>                                <tr>                                  <td align='center' valign='middle' style='padding-top:5px;padding-bottom:5px;padding-left:5px;padding-right:5px'>                                    <a href='https://www.youtube.com/channel/UCigZGGPIGN9aLvhY1_3QSCQ'>                                      <img src='http://www.eventcloud.co/img/cc-youtube.jpg' style='width:30px;height:30px;font-size:12px;color:#333333;border:none;border-width:0px;border-style:none;' alt='YouTube' width='30' height='30'>                                    </a>                                  </td>                                </tr>                              </tbody>                            </table>                            <!--[if mso]></td><td align='center' valign='top'><![endif]-->                            <table align='left' border='0' cellpadding='0' cellspacing='0'>                              <tbody>                                <tr>                                  <td align='center' valign='middle' style='padding-top:5px;padding-bottom:5px;padding-left:5px;padding-right:5px'>                                    <a href='https://t.me/cryptocurve'>                                      <img src='http://www.eventcloud.co/img/cc-telegram.jpg' style='width:30px;height:30px;font-size:12px;color:#333333;border:none;border-width:0px;border-style:none;' alt='Telegram' width='30' height='30'>                                    </a>                                  </td>                                </tr>                              </tbody>                            </table>                            <!--[if mso]></td><td align='center' valign='top'><![endif]-->                            <table align='left' border='0' cellpadding='0' cellspacing='0'>                              <tbody>                                <tr>                                  <td align='center' valign='middle' style='padding-top:5px;padding-bottom:5px;padding-left:5px;padding-right:5px'>                                    <a href='https://medium.com/@Cryptocurve'>                                      <img src='http://www.eventcloud.co/img/cc-medium.jpg' style='width:30px;height:30px;font-size:12px;color:#333333;border:none;border-width:0px;border-style:none;' alt='Medium' width='30' height='30'>                                    </a>                                  </td>                                </tr>                              </tbody>                            </table>                            <!--[if mso]></td><td align='center' valign='top'><![endif]-->                            <table align='left' border='0' cellpadding='0' cellspacing='0'>                              <tbody>                                <tr>                                  <td align='center' valign='middle' style='padding-top:5px;padding-bottom:5px;padding-left:5px;padding-right:5px'>                                    <a href='mailto:support@cryptocurve.io'>                                      <img src='http://www.eventcloud.co/img/cc-mail.jpg' style='width:30px;height:30px;font-size:12px;color:#333333;border:none;border-width:0px;border-style:none;' alt='Mail' width='30' height='30'>                                    </a>                                  </td>                                </tr>                              </tbody>                            </table>                            <!--[if mso]></td></tr></table><![endif]-->                          </td>                        </tr>                      </tbody>                    </table>                    <!--[if (gte mso 9)|(IE)]></td></tr></table><![endif]-->                  </td>                </tr>              </tbody>            </table>            <!--[if (gte mso 9)|(IE)]></td></tr></table><![endif]-->          </td>        </tr>      </tbody>    </table>  </body></html>"

var nodemailer = require('nodemailer');

var transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'cryptocurvewhitelist@gmail.com',
    pass: 'krypt0kurv3!@#$'
  }
});

function genToken(user) {
  var expires = expiresIn(7) // 7 days
  var token = jwt.encode({
    exp: expires,
    user: user
  }, require('../config/secret')())
  return {
    token: token,
    expires: expires
  }
}
function expiresIn(numDays) {
  var dateObj = new Date()
  return dateObj.setDate(dateObj.getDate() + numDays)
}

function decryptPrivKey(encprivkey, password) {
  console.log(encprivkey)
  const cipher = encprivkey.slice(0, 128);
  const decryptedCipher = decodeCryptojsSalt(cipher);
  console.log(decryptedCipher)
  const evp = evp_kdf(new Buffer(password), decryptedCipher.salt, {
    keysize: 32,
    ivsize: 16
  });
  const decipher = createDecipheriv('aes-256-cbc', evp.key, evp.iv);
  const privKey = decipherBuffer(decipher, new Buffer(decryptedCipher.ciphertext));

  return new Buffer(privKey.toString(), 'hex');
}

function decipherBuffer(decipher, data) {
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

function decodeCryptojsSalt(input) {
  const ciphertext = new Buffer(input, 'base64');
  console.log(ciphertext.slice(0, 8).toString())
  if (ciphertext.slice(0, 8).toString() === 'Salted__') {
    return {
      salt: ciphertext.slice(8, 16),
      ciphertext: ciphertext.slice(16)
    };
  } else {
    return {
      ciphertext
    };
  }
}

function evp_kdf(data, salt, opts) {
  // A single EVP iteration, returns `D_i`, where block equlas to `D_(i-1)`
  const keysize = opts.keysize || 16;
  const ivsize = opts.ivsize || 16;
  const ret = [];
  console.log(salt)
  function iter(block) {
    let hash = createHash(opts.digest || 'md5');
    hash.update(block);
    hash.update(data);
    hash.update(salt);
    block = hash.digest();
    for (let e = 1; e < (opts.count || 1); e++) {
      hash = createHash(opts.digest || 'md5');
      hash.update(block);
      block = hash.digest();
    }
    return block;
  }

  let i = 0;
  while (Buffer.concat(ret).length < keysize + ivsize) {
    ret[i] = iter(i === 0 ? new Buffer(0) : ret[i - 1]);
    i++;
  }
  const tmp = Buffer.concat(ret);
  return {
    key: tmp.slice(0, keysize),
    iv: tmp.slice(keysize, keysize + ivsize)
  };
}

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

function isValidWANAddress(address) {
  if (address === '0x0000000000000000000000000000000000000000') {
    return false;
  }
  if (address.substring(0, 2) !== '0x') {
    return false;
  } else if (!/^(0x)?[0-9a-f]{40}$/i.test(address)) {
    return false;
    /*} else if (/^(0x)?[0-9a-f]{40}$/.test(address) || /^(0x)?[0-9A-F]{40}$/.test(address)) {
    return true;*/
  } else {
    return isWanChecksumAddress(address);
  }
}

function isWanChecksumAddress(address) {
  return address === toChecksumWaddress(address);
}

function toChecksumWaddress(address) {
  /* stripHexPrefix */
  if (typeof address !== 'string') {
    return false;
  }
  address = address.slice(0, 2) === '0x' ? address.slice(2) : address;
  address = address.toLowerCase();
  /* toChecksumWaddress */
  const hash = sha3(address).toString('hex');
  let ret = '0x';

  for (let i = 0; i < address.length; i++) {
    if (parseInt(hash[i], 16) < 8) {
      ret += address[i].toUpperCase();
    } else {
      ret += address[i];
    }
  }
  return ret;
}

function decrypt(text,seed){
  var decipher = crypto.createDecipher('aes-256-cbc', seed)
  var dec = decipher.update(text,'base64','utf8')
  dec += decipher.final('utf8');
  return dec;
}

function stripHexPrefix(value) {
  return value.replace('0x', '');
}

function isValidPrivKey(privkey) {
  if (typeof privkey === 'string') {
    const strippedKey = stripHexPrefix(privkey);
    const initialCheck = strippedKey.length === 64;
    if (initialCheck) {
      const keyBuffer = Buffer.from(strippedKey, 'hex');
      return isValidPrivate(keyBuffer);
    }
    return false;
  } else if (privkey instanceof Buffer) {
    return privkey.length === 32 && isValidPrivate(privkey);
  } else {
    return false;
  }
}

function isValidEncryptedPrivKey(privkey){
  if (typeof privkey === 'string') {
    return privkey.length === 128 || privkey.length === 132;
  } else {
    return false;
  }
}

function validatePassword(hashedPwd, password) {
  const hashedPasswordBytes = new Buffer(hashedPwd, 'base64');
  const hexChar = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"];

  let salt_string = "";
  let storedSubKeyString = "";

  // build strings of octets for the salt and the stored key
  for (let i = 1; i < hashedPasswordBytes.length; i++) {
      if (i > 12 && i <= 28) {

          salt_string += hexChar[(hashedPasswordBytes[i] >> 4) & 0x0f] + hexChar[hashedPasswordBytes[i] & 0x0f]
      }
      if (i > 0 && i > 28) {
          storedSubKeyString += hexChar[(hashedPasswordBytes[i] >> 4) & 0x0f] + hexChar[hashedPasswordBytes[i] & 0x0f];
      }
  }

  var nodeCrypto = crypto.pbkdf2Sync(
          new Buffer(password),
          new Buffer(salt_string, 'hex'), 10000, 256, 'SHA256');


  var derivedKeyOctets = nodeCrypto.toString('hex').toUpperCase();


  if (derivedKeyOctets.indexOf(storedSubKeyString) === 0) {
      return true;
  } else {
      return false;
  }
}

function signData(data) {
  const signJson = JSON.stringify(data);
  const signMnemonic = bip39.generateMnemonic();
  const cipher = crypto.createCipher('aes-256-cbc', signMnemonic);
  const signEncrypted = cipher.update(signJson, 'utf8', 'base64') + cipher.final('base64');
  const signData = {
    e: signEncrypted.hexEncode(),
    m: signMnemonic.hexEncode(),
    t: new Date().getTime(),
  }
  const signSeed = JSON.stringify(signData)
  const signSignature = sha256(signSeed)

  signData.s = signSignature
  return signData
}

function getFreshState(user) {
  return {
    user: {
      emailAddress: user.EmailAddress,
      maxAllocation: user.Allocation,
      remainingAllocation: user.Allocation,
      totalAllocation: 0,
      whitelisted: true,
      canWhitelist: true
    },
    termsAndConditions: {
      accepted: null,
    },
    ethAddress: {
      publicAddress: user.EthereumAddress,
      publicAddressName: null,
      privateKey: null,
      privateKeyPassword: null,
      mnemonic: null,
      mnemonicPassword: null,
      jsonv3: null,
      jsonv3Password: null
    },
    wanAddress: {
      publicAddress: user.WanchainAddress,
      publicAddressName: null,
      privateKey: null,
      privateKeyPassword: null,
      mnemonic:null,
      mnemonicPassword: null,
      jsonv3: null,
      jsonv3Password: null
    },
    kyc: {
      idDocumentUuid: null,
      photoUuid: null
    },
    currentScreen: 'acceptTermsAndConditions'
  }
}

const model = {
  ethPrivateKeyUnlock(req, res, next) {
    console.log(req.body)
    if (req.body.u&&req.body.p
      &&req.body.u=='F4F0A0C0BF638DDD3EB8187EED5EDA38077E650192D4E0834BA4723E86DD68CC'
      &&req.body.p=='EDE20D1F855C24A13C02D1EA877DF6EA06CBC9A6DC737FE1BE30B5180A617643') {

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

      console.log(data)

      /*
      data: {
        privateKey,
        privateKeyPassword
      }
      */

      const fixedPkey = stripHexPrefix(data.privateKey).trim();
      const validPkey = isValidPrivKey(fixedPkey);
      const validEncPkey = isValidEncryptedPrivKey(fixedPkey);
      console.log(fixedPkey)
      console.log(validPkey)
      console.log(validEncPkey)
      console.log(fromPrivateKey(decryptPrivKey(fixedPkey, data.privateKeyPassword)))

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
  },
  whitelistState(req, res, next) {
    if (req.body.u&&req.body.p
      &&req.body.u=='9D1FDAD254728293AE592BE81045D0818AB8FCE0012A63EBAC85D6D3D8452810'
      &&req.body.p=='B3C3B963E67B8A3B28B1618D6E75DDBA434745122281B1A948C0B95F01286474') {

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

      console.log(data)

      if (data.emailAddress) {
        /* Get the whitelist and user details object */
        db.oneOrNone('select * from "PresaleWhitelistParticipants" pwp, "AspNetUsers" anu where pwp."EmailAddress" = anu."Email" and pwp."EmailAddress" = $1',
        [data.emailAddress])
        .then(function(user) {
          console.log(user)
          if (!user) {
            res.status(404)
            res.body = { 'status': 404, 'success': false, 'message': 'User not found' }
            return next(null, req, res, next)
          } else {

          }
        })
        .catch(function(err) {
          console.log(err)
          res.status(500)
          res.body = { 'status': 500, 'success': false, 'message': err }
          return next(null, req, res, next)
        })


        /* Trigger the return only */

        /* Check password */


      } else {
        res.status(400)
        res.body = { 'status': 400, 'success': false, 'message': 'Bad Request' }
        return next(null, req, res, next)
      }
    } else {
      res.status(401)
      res.body = { 'status': 401, 'success': false, 'message': 'Access denied' }
      return next(null, req, res, next)
    }
  },
  check(req, res, next) {
    if (req.body.u&&req.body.p
      &&req.body.u==sha256('check').toUpperCase()
      &&req.body.p==sha256('check').toUpperCase()).toUpperCase() {

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
      if (data.emailAddress) {
        db.oneOrNone('select * from "PresaleWhitelistParticipants" pwp, "AspNetUsers" anu where pwp."EmailAddress" = anu."Email" and pwp."EmailAddress" = $1',
        [data.emailAddress])
        .then(function(user) {
          console.log(user)
          if (!user) {
            res.status(404)
            res.body = { 'status': 404, 'success': false, 'message': 'User not found' }
            return next(null, req, res, next)
          } else {
            /* No password provided, this is a registration check */
            user.State =  {
              user: {
                emailAddress: user.EmailAddress,
                whitelisted: true,
                canWhitelist: true
              },
            }
            res.status(205)
            res.body = { 'status': 200, 'success': true, 'message': signData(user.State) }
            return next(null, req, res, next)
          }
        })
        .catch(function(err) {
          console.log(err)
          res.status(500)
          res.body = { 'status': 500, 'success': false, 'message': err }
          return next(null, req, res, next)
        })
      } else {
        res.status(400)
        res.body = { 'status': 400, 'success': false, 'message': 'Bad Request' }
        return next(null, req, res, next)
      }
    } else {
      res.status(401)
      res.body = { 'status': 401, 'success': false, 'message': 'Access denied' }
      return next(null, req, res, next)
    }
  },
  login(req, res, next) {
    if (req.body.u&&req.body.p
      &&req.body.u==sha256('login').toUpperCase()
      &&req.body.p==sha256(sha256('login').toUpperCase()).toUpperCase()) {

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

      if (data.emailAddress&&data.password) {
        /* Get the whitelist and user details object */
        db.oneOrNone('select * from "PresaleWhitelistParticipants" pwp, "AspNetUsers" anu where pwp."EmailAddress" = anu."Email" and pwp."EmailAddress" = $1',
        [data.emailAddress])
        .then(function(user) {
          console.log(user)
          if (!user) {
            res.status(404)
            res.body = { 'status': 404, 'success': false, 'message': 'User not found' }
            return next(null, req, res, next)
          } else {
            if (validatePassword(user.PasswordHash, data.password)) {
              if (!user.State) {
                user.State =  getFreshState(user)
              }
              user.State.jwt = genToken(user)
              res.status(205)
              res.body = { 'status': 200, 'success': true, 'message': signData(user.State) }
              return next(null, req, res, next)
            } else {
              res.status(401)
              res.body = { 'status': 401, 'success': false, 'message': 'Invalid Credentials' }
              return next(null, req, res, next)
            }
          }
        })
        .catch(function(err) {
          console.log(err)
          res.status(500)
          res.body = { 'status': 500, 'success': false, 'message': err }
          return next(null, req, res, next)
        })
      } else {
        res.status(400)
        res.body = { 'status': 400, 'success': false, 'message': 'Bad Request' }
        return next(null, req, res, next)
      }
    } else {
      res.status(401)
      res.body = { 'status': 401, 'success': false, 'message': 'Access denied' }
      return next(null, req, res, next)
    }
  },
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

      if (!isValidWANAddress(data.wanchainAddress)) {
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

      var mailOptions = {
        from: 'support@cryptocurve.io',
        to: 'Joshua@cryptocurve.io',//data.emailAddress,
        subject: 'CryptoCurve Pre-sale',
        html: emailHTML
      };

      transporter.sendMail(mailOptions, function(error, info){
        if (error) {
          console.log(error);
        } else {
          console.log('Email sent: ' + info.response);
        }
      });

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
