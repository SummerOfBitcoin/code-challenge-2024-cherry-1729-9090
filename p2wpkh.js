const { createHash } = require('crypto');
const { sha256, ripemd160, OP_HASH160,doubleHash } = require('./hashes.js');
const crypto = require('crypto');
const { verifyECDSASignature } = require('./functions.js');

function littleEndian(data) {
  const pairs = [];
  for (let i = 0; i < data.length; i += 2) {
    pairs.unshift(data.substring(i, i + 2));
  }
  return pairs.join('');
}


function hashPrevouts(transaction) {
    const vin = transaction.vin;
    let concStr = "";
    for (const vinEntry of vin) {
      const voutString = vinEntry.vout.toString(16).padStart(8, '0');
      concStr += littleEndian(vinEntry.txid) + littleEndian(voutString);
    }
    return doubleHash(concStr);
  }
  
function hashSequences(transaction) {
  const vin = transaction.vin;
  let concStr = "";
  for (const vinEntry of vin) {
    const sequenceString = vinEntry.sequence
                            .toString(16)
                            .padStart(8, '0');
    concStr += littleEndian(sequenceString);
  }
  return doubleHash(concStr);
}

function hashOutputs(transaction) {
  const vout = transaction.vout;
  let concBytes = ""
  for (const voutEntry of vout) {
      concBytes += littleEndian(voutEntry.value.toString(16).padStart(16, '0')) ;
      concBytes += (voutEntry.scriptpubkey.length / 2).toString(16).padStart(2,'0');
      concBytes += voutEntry.scriptpubkey ;
  }
  return doubleHash(concBytes);
}



function outpoints(transaction,index) {
  const vin = transaction.vin;
  let concStr = "";
  vinEntry = vin[index]
  concStr += littleEndian(vinEntry.txid) + 
            littleEndian((vinEntry.vout).toString(16).padStart(8, '0'));
  return concStr;
}


function scriptCode(transaction,inputIndex) {
  return "1976a914" +
  transaction.vin[inputIndex].prevout.scriptpubkey.slice(4) +
  "88ac"; //script code for p2wpkh
}

function amount(transaction,index) {
  return littleEndian(transaction.vin[index].prevout.value.toString(16).padStart(16, '0'));
}

function nsequence(transaction,index) {
  return littleEndian(transaction.vin[index].sequence.toString(16).padStart(8, '0'));
}

function serializeP2WPKH(transaction,index) {
  const serializedTxn = littleEndian(transaction.version.toString(16).padStart(8, '0')) +
    hashPrevouts(transaction) +
    hashSequences(transaction) +
    outpoints(transaction,index) +
    scriptCode(transaction,index) +
    amount(transaction,index) +
    nsequence(transaction,index)+
    hashOutputs(transaction) +
    littleEndian(transaction.locktime.toString(16).padStart(8,'0')) +
    "01000000";
  return doubleHash(serializedTxn);
  // return serializedTxn;
}




function checkSig_p2wpkh(transaction){
  for (let i = 0; i < transaction.vin.length; i++) {
    serialization = serializeP2WPKH(transaction,i);
    pubkey = transaction.vin[i].witness[1];
    sig = transaction.vin[i].witness[0];
    if (!verifyECDSASignature(pubkey, sig, serialization)) {
      return false;
    }
    return true;
  }
}


module.exports = { checkSig_p2wpkh };