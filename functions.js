const { Hash } = require('sha256');
const crypto = require('crypto');
const EC = require('elliptic').ec;
const ecdsa = new EC('secp256k1');
const { createHash } = require('crypto');
const { verify } = require('crypto');
const {sha256} = require('./hashes')


function toHex(value) {
    return value.toString(16).padStart((value.toString(16).length % 2 === 0) ? value.toString(16).length : value.toString(16).length + 1, '0');
  }
  
function littleEndian(data) {
    let pairs = [];
    for (let i = 0; i < data.length; i += 2) {
      pairs.unshift(data.substring(i, i + 2));
    }
    return pairs.join('');
  }
  

function ripemd160(data) {
  const hash = crypto.createHash('ripemd160');
  hash.update(data);
  return hash.digest('hex');
}


function doubleHash(dataHex) {
  const firstHash = crypto.createHash('sha256').update(Buffer.from(dataHex, 'hex')).digest('hex');
  const secondHash = crypto.createHash('sha256').update(Buffer.from(firstHash, 'hex')).digest('hex');
  return secondHash;
}

function concVin(transaction) {
  let concatStr = "";
  transaction.vin.forEach(vin => {
    const sigSize = vin.scriptsig.length / 2;
    concatStr += littleEndian(vin.txid) + littleEndian(toHex(vin.vout).padStart(8, '0')) + toHex(sigSize).padStart(2, '0') + vin.scriptsig + littleEndian(toHex(vin.sequence));
  });
  return concatStr;
}

function concVout(transaction) {
  let concatStr = "";
  transaction.vout.forEach(vout => {
    concatStr += littleEndian(vout.value.toString(16).padStart(16, '0')) + toHex(vout.scriptpubkey.length / 2).padStart(2, '0') + vout.scriptpubkey;
  });
  return concatStr;
}

function serializeP2pkh(transaction) {
  const serializeP2pkh = littleEndian(transaction.version.toString(16).padStart(8, '0')) +
    toHex(transaction.vin.length).padStart(2, '0') +
    concVin(transaction) +
    transaction.vout.length.toString(16).padStart(2, '0') +
    concVout(transaction) +
    littleEndian(toHex(transaction.locktime)).padEnd(8, '0');
  return doubleHash(serializeP2pkh);
}

function verifyFiles(data) {
  const data1 = littleEndian(serializeP2pkh(data));
  const dataBytes = Buffer.from(data1, 'hex');
  return crypto.createHash('sha256').update(dataBytes).digest('hex') + '.json';
}

function createVinDigest(transaction, index) {
  let concatStr = "";
  const vin = transaction.vin;
  vin.forEach((vin, i) => {
    if (i === index) {
      concatStr += littleEndian(vin.txid) + littleEndian(toHex(vin.vout).padStart(8, '0')) + littleEndian(toHex(vin.prevout.scriptpubkey.length / 2).padStart(2, '0')) + vin.prevout.scriptpubkey + littleEndian(toHex(vin.sequence));
    } else {
      concatStr += littleEndian(vin.txid) + littleEndian(toHex(vin.vout).padStart(8, '0')) + '00' + littleEndian(toHex(vin.sequence));
    }
  });
  return concatStr;
}

function createDigest(transaction, index) {
  const concatStr = littleEndian(transaction.version.toString(16).padStart(8, '0')) +
    toHex(transaction.vin.length).padStart(2, '0') +
    createVinDigest(transaction, index) +
    transaction.vout.length.toString(16).padStart(2, '0') +
    concVout(transaction) +
    littleEndian(toHex(transaction.locktime)).padEnd(8, '0') +
    "01000000";
  return doubleHash(concatStr);
}


function parseDER(serialized) {
    // Extract the length of the R element
    const rLength = parseInt(serialized.substring(6, 8), 16) * 2;
    // Calculate the start and end positions of R
    const rStart = 8;
    const rEnd = rStart + rLength;
    // Extract R
    const r = serialized.substring(rStart, rEnd);
  
    // Extract the length of the S element
    const sLength = parseInt(serialized.substring(rEnd + 2, rEnd + 4), 16) * 2;
    // Calculate the start and end positions of S
    const sStart = rEnd + 4;
    const sEnd = sStart + sLength;
    // Extract S
    const s = serialized.substring(sStart, sEnd);
    return { r, s };
  }

  function verifyECDSASignature(publicKeyHex, signatureHex, messageHex) {
    const ecdsa = new EC("secp256k1");
    const key = ecdsa.keyFromPublic(publicKeyHex, "hex");
    const signature = parseDER(signatureHex);
    const isValid = key.verify(messageHex, signature);
    return isValid;
  }
  
  function checkSigP2PKH(transaction, i) {
    const message = createDigest(transaction, i);
    const isValid = verifyECDSASignature(transaction.vin[i].scriptsig_asm.split(' ')[3], transaction.vin[i].scriptsig_asm.split(' ')[1], message);
    if (isValid) {
        console.log("yes");
    }
}

function checkStack(transaction) {
    let index = 0;
    const vin = transaction.vin;
    for (const vin_entry of vin) {
        const stack = [];
        const vin_asm = vin_entry.scriptsig_asm.split(' ');
        
        stack.push(vin_asm[1]);
        
        stack.push(vin_asm[3]);
        const script = vin_entry.prevout.scriptpubkey_asm.split(' ');
        for (let i = 0; i < script.length; i++) {
            if (script[i] === 'OP_DUP') {
                stack.push(stack[stack.length - 1]);
                // console.log(stack);
            } else if (script[i] === 'OP_HASH160') {
                stack.pop();
                const data = crypto.createHash('sha256').update(Buffer.from(stack[stack.length - 1], 'hex')).digest();
                const hexHashedValue = ripemd160(data);
                // console.log(hexHashedValue);
                stack.push(hexHashedValue);
                // console.log(stack);
            } else if (script[i] === 'OP_PUSHBYTES_20') {
                stack.push(script[i + 1]);
                // console.log(stack);
            } else if (script[i] === 'OP_EQUALVERIFY') {
                // console.log(stack[stack.length - 1], stack[stack.length - 2]);
                if (stack[stack.length - 1] === stack[stack.length - 2]) {
                    stack.pop();
                    stack.pop();
                } else {
                    return false;
                }
                // console.log(stack);
            } else if (script[i] === 'OP_CHECKSIG') {
                // console.log("*****");
                const msgDigest = createDigest(transaction, index);
                // console.log(msgDigest + "      ******* ");
                const pubkey = stack.pop();
                // console.log(pubkey);
                const signature = stack.pop();
                // console.log(signature);
                const isValid = verifyECDSASignature(pubkey, signature, msgDigest);
                // console.log(stack);
            }
        }
        index++;
    }
    return true;
}



tx = {
  "version": 2,
  "locktime": 832539,
  "vin": [
    {
      "txid": "7c218cbf0fe023d15b71e401b34d6841f3cdf5617a42eddf32708fcf4c3236cb",
      "vout": 0,
      "prevout": {
        "scriptpubkey": "76a9144e30f8fd336a83e1d6910fb9713d21f6dda1ff5a88ac",
        "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 4e30f8fd336a83e1d6910fb9713d21f6dda1ff5a OP_EQUALVERIFY OP_CHECKSIG",
        "scriptpubkey_type": "p2pkh",
        "scriptpubkey_address": "188SNe6fRhVm2hd3PZ3TwsBSWchFZak2Th",
        "value": 36882
      },
      "scriptsig": "47304402202bce610e94ec86bcdda2622158bd021640722acbbbb506cc11fb3c1a10b5d562022014bd28a276f44a86b9987daa0555525d60f602b2f52ef4bd4e07f9bad8041b6c01210227ce4c39213f865f1c18987079557548748e83126fcc11293fbd8eac4b0671eb",
      "scriptsig_asm": "OP_PUSHBYTES_71 304402202bce610e94ec86bcdda2622158bd021640722acbbbb506cc11fb3c1a10b5d562022014bd28a276f44a86b9987daa0555525d60f602b2f52ef4bd4e07f9bad8041b6c01 OP_PUSHBYTES_33 0227ce4c39213f865f1c18987079557548748e83126fcc11293fbd8eac4b0671eb",
      "is_coinbase": false,
      "sequence": 4294967293
    },
    {
      "txid": "869b62369426bac43369b49e62f5611f94f808a7c670875831c7f593eb7b5ba9",
      "vout": 0,
      "prevout": {
        "scriptpubkey": "76a914d74bce8fd3488eed4d449351feafdaca1d03b7d688ac",
        "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 d74bce8fd3488eed4d449351feafdaca1d03b7d6 OP_EQUALVERIFY OP_CHECKSIG",
        "scriptpubkey_type": "p2pkh",
        "scriptpubkey_address": "1LdP6Q62wHkZwoBE62Gy4y2tuw9kZhTqmv",
        "value": 328797
      },
      "scriptsig": "473044022019d625e3d2a77df31515113790c90c2f00e9200b22010717329a878246c9881e02203970dafda92f72cf3d8579509907e41099e9bdd6f3541eb46a6806697f407dd2012102a17743cdc1bf0f9adab350bba42658fca42c0d486ab0cc49e2451bb5be2295a7",
      "scriptsig_asm": "OP_PUSHBYTES_71 3044022019d625e3d2a77df31515113790c90c2f00e9200b22010717329a878246c9881e02203970dafda92f72cf3d8579509907e41099e9bdd6f3541eb46a6806697f407dd201 OP_PUSHBYTES_33 02a17743cdc1bf0f9adab350bba42658fca42c0d486ab0cc49e2451bb5be2295a7",
      "is_coinbase": false,
      "sequence": 4294967293
    },
    {
      "txid": "c0f0cf3896308fabf365f9430a5d42265efe4b9bda12f61e5146c21aed1b88f6",
      "vout": 0,
      "prevout": {
        "scriptpubkey": "76a9143b5428c5c51348a788afd5cc362f227d4c04c66288ac",
        "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 3b5428c5c51348a788afd5cc362f227d4c04c662 OP_EQUALVERIFY OP_CHECKSIG",
        "scriptpubkey_type": "p2pkh",
        "scriptpubkey_address": "16Qhgomq9Jnh247Q5KCzXvLXhZv1VBzTrS",
        "value": 34100
      },
      "scriptsig": "473044022034fdb2fdcf5b147f81c4a13350e9ee8c9f5de08d27103cf65e6a7c3b96042d2202206186ce4aa966c16e4671a35f766c17382c9c758d1622ef59bba6ef571c679f7a012103d23ad1dccc41cf313e2355fe220238260efde1fc156a9c4f7211898229db1139",
      "scriptsig_asm": "OP_PUSHBYTES_71 3044022034fdb2fdcf5b147f81c4a13350e9ee8c9f5de08d27103cf65e6a7c3b96042d2202206186ce4aa966c16e4671a35f766c17382c9c758d1622ef59bba6ef571c679f7a01 OP_PUSHBYTES_33 03d23ad1dccc41cf313e2355fe220238260efde1fc156a9c4f7211898229db1139",
      "is_coinbase": false,
      "sequence": 4294967293
    },
    {
      "txid": "f4482b2a061a321965c7ad1768fc80599ce36fbf693cfd95d23dd708e22c45cc",
      "vout": 0,
      "prevout": {
        "scriptpubkey": "76a914529a520fba93f9940fc113c803e04fb8e378af1c88ac",
        "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 529a520fba93f9940fc113c803e04fb8e378af1c OP_EQUALVERIFY OP_CHECKSIG",
        "scriptpubkey_type": "p2pkh",
        "scriptpubkey_address": "18XmH7PEgjmBLqeee2nSSV6Qm5C5x2JNxs",
        "value": 41184
      },
      "scriptsig": "47304402207d9a086b835659c2f45de8d2d85292f04ce8b833969cdd4f352b679a7b3775940220050cfec89f5a309799f3dc0628ff20fb696c43b1c6bee93066dfdab089da50b301210281e3301ea2655d695a1950f59456b27f8f3fbc0bbe6349cedc4121052a36b816",
      "scriptsig_asm": "OP_PUSHBYTES_71 304402207d9a086b835659c2f45de8d2d85292f04ce8b833969cdd4f352b679a7b3775940220050cfec89f5a309799f3dc0628ff20fb696c43b1c6bee93066dfdab089da50b301 OP_PUSHBYTES_33 0281e3301ea2655d695a1950f59456b27f8f3fbc0bbe6349cedc4121052a36b816",
      "is_coinbase": false,
      "sequence": 4294967293
    }
  ],
  "vout": [
    {
      "scriptpubkey": "76a914090a212ddb7211158409534bce9f6d553bcd028788ac",
      "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 090a212ddb7211158409534bce9f6d553bcd0287 OP_EQUALVERIFY OP_CHECKSIG",
      "scriptpubkey_type": "p2pkh",
      "scriptpubkey_address": "1poDYYTsXhXimWRiKRjVCokoLzzbjR25q",
      "value": 24200
    },
    {
      "scriptpubkey": "a914f15ac47ae6eb8f8da450ba7787b6a8c0059b076087",
      "scriptpubkey_asm": "OP_HASH160 OP_PUSHBYTES_20 f15ac47ae6eb8f8da450ba7787b6a8c0059b0760 OP_EQUAL",
      "scriptpubkey_type": "p2sh",
      "scriptpubkey_address": "3PhBWQp766Lr5p4HqWFkEsMraLW2h918LV",
      "value": 410000
    }
  ]
}


  



  module.exports = { verifyFiles,checkStack,verifyECDSASignature,createDigest,parseDER,checkSigP2PKH,createVinDigest,serializeP2pkh,concVout,concVin,doubleHash,littleEndian,ripemd160,toHex };
