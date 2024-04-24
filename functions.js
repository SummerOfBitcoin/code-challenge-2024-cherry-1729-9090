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
  const secondHash = crypto.createHash('sha256').update(firstHash, 'hex').digest('hex');
  return secondHash;
}

function concVin(transaction) {
  let concatStr = "";
  transaction.vin.forEach(vin => {
    const sigSize = vin.scriptsig.length / 2;
    concatStr += littleEndian(vin.txid) + littleEndian(toHex(vin.vout).padStart(8, '0')) + (sigSize).toString(16).padStart(2, '0') + vin.scriptsig + littleEndian((vin.sequence).toString(16));
  });
  return concatStr;
}

function concVout(transaction) {
  let concatStr = "";
  transaction.vout.forEach(vout => {
    concatStr += littleEndian(vout.value.toString(16).padStart(16, '0')) + toHex(vout.scriptpubkey.length / 2).toString(16).padStart(2, '0') + vout.scriptpubkey;
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



module.exports = { verifyFiles,checkStack,verifyECDSASignature,createDigest,parseDER,checkSigP2PKH,createVinDigest,serializeP2pkh,concVout,concVin,doubleHash,littleEndian,ripemd160,toHex };





tx = {
  "txid": "d63e67e47999283ee784f959edef4ff80b507b06b03623030d7c3042e709047b",
  "version": 2,
  "locktime": 0,
  "vin": [
    {
      "txid": "32edfb6330b27344f88655887d3ef2258a1281b6a9cc95ee02ff4f2188e91d5d",
      "vout": 0,
      "prevout": {
        "scriptpubkey": "76a9147e00ab284ace44f6cf1274957f2b743b233a2f6688ac",
        "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 7e00ab284ace44f6cf1274957f2b743b233a2f66 OP_EQUALVERIFY OP_CHECKSIG",
        "scriptpubkey_type": "p2pkh",
        "scriptpubkey_address": "1CVEwdEGQHrwxu17Mbq5U1d9y34VHBscXE",
        "value": 29390611
      },
      "scriptsig": "4830450221008d6c25a55640e5e6a86e9115e02b2549f95eb8f980435afbc0ab5686abe0a6430220163d6d208d87890d63d90af8136cd8fc4461d5354bf2a950a11e47d2874d355c012103442520eb769b97b1f4d0f727a795351150a449a08f69079fb7363f4880bd6f63",
      "scriptsig_asm": "OP_PUSHBYTES_72 30450221008d6c25a55640e5e6a86e9115e02b2549f95eb8f980435afbc0ab5686abe0a6430220163d6d208d87890d63d90af8136cd8fc4461d5354bf2a950a11e47d2874d355c01 OP_PUSHBYTES_33 03442520eb769b97b1f4d0f727a795351150a449a08f69079fb7363f4880bd6f63",
      "is_coinbase": false,
      "sequence": 4294967293
    },
    {
      "txid": "48aa0c5aae0065e12c256663f408626faeb99602a139cbdd961c85d1e2b3d7a4",
      "vout": 0,
      "prevout": {
        "scriptpubkey": "76a9147e00ab284ace44f6cf1274957f2b743b233a2f6688ac",
        "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 7e00ab284ace44f6cf1274957f2b743b233a2f66 OP_EQUALVERIFY OP_CHECKSIG",
        "scriptpubkey_type": "p2pkh",
        "scriptpubkey_address": "1CVEwdEGQHrwxu17Mbq5U1d9y34VHBscXE",
        "value": 9037968
      },
      "scriptsig": "483045022100ea8f9b4c918c283bcc16ca1c99d33409e25f50d37fff8f321e95d5cf8516a04e022006e16fab2df84bf279aa09bc7ee843a836c8259003973551d99c477f1abde253012103442520eb769b97b1f4d0f727a795351150a449a08f69079fb7363f4880bd6f63",
      "scriptsig_asm": "OP_PUSHBYTES_72 3045022100ea8f9b4c918c283bcc16ca1c99d33409e25f50d37fff8f321e95d5cf8516a04e022006e16fab2df84bf279aa09bc7ee843a836c8259003973551d99c477f1abde25301 OP_PUSHBYTES_33 03442520eb769b97b1f4d0f727a795351150a449a08f69079fb7363f4880bd6f63",
      "is_coinbase": false,
      "sequence": 4294967293
    },
    {
      "txid": "f3dbebf377c2ddaba0bdc9731c0cafa5e6057534cb1885493c7499cfdce11972",
      "vout": 1,
      "prevout": {
        "scriptpubkey": "001457f5cb1cb375d7e487c9d02f4d581df5c5d7a51f",
        "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_20 57f5cb1cb375d7e487c9d02f4d581df5c5d7a51f",
        "scriptpubkey_type": "v0_p2wpkh",
        "scriptpubkey_address": "bc1q2l6uk89nwht7fp7f6qh56kqa7hza0fglh9pze6",
        "value": 13580
      },
      "scriptsig": "",
      "scriptsig_asm": "",
      "witness": [
        "3045022100c1015c8af17423a0e40d8159156d992eb253f12c4fd64e4f9db78621489de1bc022066007488c824a0ecfd62cd593f66a726e1e1d7b55f898328a49fabf3557fc03801",
        "03f00d8ca2c0ba3b5a594465cdff97973c893777932ede0cde1ffa98f06868acec"
      ],
      "is_coinbase": false,
      "sequence": 4294967293
    },
    {
      "txid": "f7e70896b5c4c510b58f7d679c7df69953ffb4eb49e8f68c5ebab4440b763a81",
      "vout": 0,
      "prevout": {
        "scriptpubkey": "76a9147e00ab284ace44f6cf1274957f2b743b233a2f6688ac",
        "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 7e00ab284ace44f6cf1274957f2b743b233a2f66 OP_EQUALVERIFY OP_CHECKSIG",
        "scriptpubkey_type": "p2pkh",
        "scriptpubkey_address": "1CVEwdEGQHrwxu17Mbq5U1d9y34VHBscXE",
        "value": 700549
      },
      "scriptsig": "4830450221008fa5e43eee0c74dcaf25f3b110951617a023d5601e4b2c20174addc2ec703b4602207755d08a00449cbf208bd8c84235d0188a524778d6e20bbd3ae0c6676f4be2c6012103442520eb769b97b1f4d0f727a795351150a449a08f69079fb7363f4880bd6f63",
      "scriptsig_asm": "OP_PUSHBYTES_72 30450221008fa5e43eee0c74dcaf25f3b110951617a023d5601e4b2c20174addc2ec703b4602207755d08a00449cbf208bd8c84235d0188a524778d6e20bbd3ae0c6676f4be2c601 OP_PUSHBYTES_33 03442520eb769b97b1f4d0f727a795351150a449a08f69079fb7363f4880bd6f63",
      "is_coinbase": false,
      "sequence": 4294967293
    },
    {
      "txid": "242d82904b8e7def2d0a37a55da6aeaa9d372ab18784381acb53ee364d0b35bb",
      "vout": 0,
      "prevout": {
        "scriptpubkey": "76a9147e00ab284ace44f6cf1274957f2b743b233a2f6688ac",
        "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 7e00ab284ace44f6cf1274957f2b743b233a2f66 OP_EQUALVERIFY OP_CHECKSIG",
        "scriptpubkey_type": "p2pkh",
        "scriptpubkey_address": "1CVEwdEGQHrwxu17Mbq5U1d9y34VHBscXE",
        "value": 547424
      },
      "scriptsig": "4730440220465fa2f5bf3b440f8140d5d2ea2161bf7201bbac1e78271dd8bb8a52f170c179022059a8223a0c49500c4cd5d61a2cf3c164e330a979529aa1aa2231074df7d9fcf6012103442520eb769b97b1f4d0f727a795351150a449a08f69079fb7363f4880bd6f63",
      "scriptsig_asm": "OP_PUSHBYTES_71 30440220465fa2f5bf3b440f8140d5d2ea2161bf7201bbac1e78271dd8bb8a52f170c179022059a8223a0c49500c4cd5d61a2cf3c164e330a979529aa1aa2231074df7d9fcf601 OP_PUSHBYTES_33 03442520eb769b97b1f4d0f727a795351150a449a08f69079fb7363f4880bd6f63",
      "is_coinbase": false,
      "sequence": 4294967293
    },
    {
      "txid": "6afebd807c8984e50b1458b0aa3f4371f03f6f8f6bb7309a8b248a6115cd9c3d",
      "vout": 0,
      "prevout": {
        "scriptpubkey": "76a9147e00ab284ace44f6cf1274957f2b743b233a2f6688ac",
        "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 7e00ab284ace44f6cf1274957f2b743b233a2f66 OP_EQUALVERIFY OP_CHECKSIG",
        "scriptpubkey_type": "p2pkh",
        "scriptpubkey_address": "1CVEwdEGQHrwxu17Mbq5U1d9y34VHBscXE",
        "value": 1287906
      },
      "scriptsig": "4830450221009c10ef351650eacfa9d4a933a4657dfdd0c65a5092695d3ce2f310614f7d1bd002204a8f0fd76d9befb79767041fa0123e41906d858bf3008b653349517e7b7e270d012103442520eb769b97b1f4d0f727a795351150a449a08f69079fb7363f4880bd6f63",
      "scriptsig_asm": "OP_PUSHBYTES_72 30450221009c10ef351650eacfa9d4a933a4657dfdd0c65a5092695d3ce2f310614f7d1bd002204a8f0fd76d9befb79767041fa0123e41906d858bf3008b653349517e7b7e270d01 OP_PUSHBYTES_33 03442520eb769b97b1f4d0f727a795351150a449a08f69079fb7363f4880bd6f63",
      "is_coinbase": false,
      "sequence": 4294967293
    },
    {
      "txid": "4df31ded7b4a7c28cd182d1e9b362a6a7e4fad4ac8231fec4d93785960173544",
      "vout": 1,
      "prevout": {
        "scriptpubkey": "001457f5cb1cb375d7e487c9d02f4d581df5c5d7a51f",
        "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_20 57f5cb1cb375d7e487c9d02f4d581df5c5d7a51f",
        "scriptpubkey_type": "v0_p2wpkh",
        "scriptpubkey_address": "bc1q2l6uk89nwht7fp7f6qh56kqa7hza0fglh9pze6",
        "value": 3129839
      },
      "scriptsig": "",
      "scriptsig_asm": "",
      "witness": [
        "304402206160c6fa6b90558ae18ffd540ed908148b31a3c594152e3c1c96b0f6be1ef841022050fea29bd6e0c7f9254fd40ef7a7132b32db36e0e12b851867db6848b4e2868001",
        "03f00d8ca2c0ba3b5a594465cdff97973c893777932ede0cde1ffa98f06868acec"
      ],
      "is_coinbase": false,
      "sequence": 4294967293
    }
  ],
  "vout": [
    {
      "scriptpubkey": "0014c9ca81f8508e870b8baecc4ac4d2fed294a4d921",
      "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_20 c9ca81f8508e870b8baecc4ac4d2fed294a4d921",
      "scriptpubkey_type": "v0_p2wpkh",
      "scriptpubkey_address": "bc1qe89gr7zs36rshzawe39vf5h76222fkfpxvsywe",
      "value": 44094176
    }
  ]
}


console.log(littleEndian(serializeP2pkh(tx)));