const crypto = require('crypto')

const hashedPwd =   "AQAAAAEAACcQAAAAEGCyFaf5Zc+kgZRJFaonfJJHSaMTBNKDUrYbwenLnUEPXB/+nbDdsHRvyYzABMqUVw==";
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

// password provided by the user
const password = '12345678';

var nodeCrypto = crypto.pbkdf2Sync(
        new Buffer(password),
        new Buffer(salt_string, 'hex'), 10000, 256, 'SHA256');


var derivedKeyOctets = nodeCrypto.toString('hex').toUpperCase();


if (derivedKeyOctets.indexOf(storedSubKeyString) === 0) {
    console.log("passwords match!");
} else {
    console.log("passwords DO NOT match!");
}
