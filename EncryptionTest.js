const aes256 = require('aes256');
const bip39 = require('bip39');
const sha256 = require('sha256');
const crypto = require('crypto-browserify')

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

var d = {
  privateKey : "0x0204bd16fac281df38fdbf94e08f139bdd2c4c2e954dbcd22932aab7286ba47063020470d6b8ce0814d4998d5b93a44bded8726be8fdeb216e0a98097e2d733ef349",
  privateKeyPassword : "0x1e321be460b5b056e861f682323fdf1511d275c7"
}
d = {
  emailAddress: "andre@cryptocurve.io",
  password: "12345678"
}
const json = JSON.stringify(d);

function decrypt(text,seed){
  var decipher = crypto.createDecipher('aes-256-cbc', seed)
  var dec = decipher.update(text,'base64','utf8')
  dec += decipher.final('utf8');
  return dec;
}

console.log(json)

const mnemonic = bip39.generateMnemonic();

console.log(mnemonic)

const cipher = crypto.createCipher('aes-256-cbc', mnemonic);
const encrypted = cipher.update(json, 'utf8', 'base64') + cipher.final('base64');

const data = {
  e: encrypted.hexEncode(),
  m: mnemonic.hexEncode(),
  u: '9D1FDAD254728293AE592BE81045D0818AB8FCE0012A63EBAC85D6D3D8452810',
  p: 'B3C3B963E67B8A3B28B1618D6E75DDBA434745122281B1A948C0B95F01286474',
  t: new Date().getTime(),
}
const seed = JSON.stringify(data)
const signature = sha256(seed)

data.s = signature

console.log(JSON.stringify(data))

const dMnemonic = data.m.hexDecode()
const dEncrypted = data.e.hexDecode()
const dTime = data.t
const dSignature = data.s

const sig = {
  e: data.e,
  m: data.m,
  t: data.t
}
const dSeed = JSON.stringify(sig)
const compareSignature = sha256(dSeed)

if (compareSignature !== dSignature) {

}
const payload = decrypt(dEncrypted, dMnemonic)
var unencrypted = null
try {
   unencrypted = JSON.parse(payload)
} catch (ex) {

}
console.log(unencrypted)
