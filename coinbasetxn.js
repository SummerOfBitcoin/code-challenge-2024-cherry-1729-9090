const { serializeP2pkh, littleEndian, verifyFiles, doubleHash, checkSigP2PKH, checkStack } = require("./functions");
const { create_wtxid } = require('./wtxid.js');
const {sha256} = require('./hashes.js');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { checkSig_p2wpkh } = require("./p2wpkh.js");
const {calculateTransactionWeight} = require("./txweight.js")

let wtxns = [];
let txAll = []



// directory where the files are stored
const directory = './mempool';


// function to generate the merkle root
const generateMerkleRoot = (txids) => {
    if (txids.length === 0) return null

  // reverse the txids
  let level = txids.map((txid) => Buffer.from(txid, 'hex').reverse().toString('hex'))

  while (level.length > 1) {
    const nextLevel = []

    for (let i = 0; i < level.length; i += 2) {
      let pairHash
      if (i + 1 === level.length) {
        // In case of an odd number of elements, duplicate the last one
        pairHash = doubleHash(level[i] + level[i])
      } else {
        pairHash = doubleHash(level[i] + level[i + 1])
      }
      nextLevel.push(pairHash)
    }

    level = nextLevel
  }

  return level[0]
  };


  // function to generate the coinbase transaction
  function generate_coinbase_tx(wtxns){
    wtxns.unshift('0'.padStart(64,'0')); // add the coinbase txid to the wtxns array
    // console.log(wtxns);
      const witness_commitment = generate_witness_commitment(generateMerkleRoot(wtxns));
      console.log("wcom",witness_commitment)
      const scriptpubkey = '6a24aa21a9ed' + witness_commitment.toString('hex'); // Concatenate with the hexadecimal string of witness_commitment
      const scriptsig = "49366144657669436872616E496C6F7665426974636F696E4D696E696E67"; // coinbase scriptSig
      let coinbase_tx = "";
      coinbase_tx += "01000000"; // version
          // 8
      coinbase_tx += "0001"; // marker + flag //4
         // 12
      coinbase_tx += "01"; // number of inputs //2
         // 14
      coinbase_tx += "0000000000000000000000000000000000000000000000000000000000000000"  //64
          // 78
      coinbase_tx += "ffffffff"; // previous output // 8
         // 86
      coinbase_tx += "25246920616d206e61726173696d686120616e64206920616d20736f6c76696e672062697463"; // coinbase scriptSig // 37 
      coinbase_tx += "ffffffff"; // sequence
      coinbase_tx += "02"; // number of outputs

      //output 1
      coinbase_tx += "f595814000000000"; // value - 1
      coinbase_tx += "19" // size of scriptpubkey
      coinbase_tx += "76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac"; // scriptpubkey

      //output 2
      coinbase_tx += "0000000000000000" // value - 2
      coinbase_tx += (scriptpubkey.length/2).toString(16) + scriptpubkey; // scriptpubkey
      coinbase_tx += "01"; // number of witnesses
      coinbase_tx += "20"; // size of witness commitment
      coinbase_tx += "0000000000000000000000000000000000000000000000000000000000000000";
      coinbase_tx += "00000000"; // locktime
      return coinbase_tx;
  }
  
  function generate_witness_commitment(W_merkleroot){
      return doubleHash( W_merkleroot + "0".padStart(64,'0'));
  }


// read all the files in the directory
const targetweight = 4 * 1000 *1000
let weightTill = 320 // block weight
try {
    const files = fs.readdirSync(directory);
    for (const filename of files) {
        const filepath = path.join(directory, filename);
        const fileData = fs.readFileSync(filepath, 'utf8');
        const data = JSON.parse(fileData);
        const transactionType = data.vin[0].prevout.scriptpubkey_type;
        const fileVerification = verifyFiles(data);
        if (transactionType === "p2pkh") {
            if (filename === fileVerification) {
                if (checkStack(data)){
                    if( calculateTransactionWeight(data)){
                        weightTill += calculateTransactionWeight(data); // calculating the transaction weight 
                        if(weightTill < targetweight){
                            wtxns.push(littleEndian(serializeP2pkh(data))); //pushing the little endain form of the normal txid
                            txAll.push(littleEndian(serializeP2pkh(data)));
                        }else{
                            weightTill += calculateTransactionWeight(data); // calculating the transaction weight
                            break;
                        }
                    }
                }
            }
        }

        if (transactionType === "v0_p2wpkh") {
            if (filename === fileVerification) {
               if (checkSig_p2wpkh(data)){ 
                    if(calculateTransactionWeight(data)){
                        weightTill += calculateTransactionWeight(data); // calculating the transaction weight
                        if(weightTill < targetweight){
                            wtxns.push(littleEndian(create_wtxid(data))); //pushing the little endain form of the wtxid
                            txAll.push(littleEndian(serializeP2pkh(data)))
                        }
                        else{
                            weightTill += calculateTransactionWeight(data); // calculating the transaction weight
                            break;
                        }
                    }
               }
            }

        }
    }


} catch (err) {
    console.error('Error:', err);
}





// write all the wtxns to a file
const fileName = 'wtxns.txt';
const fileContent = `wtxns:\n[${wtxns.map(item => `\n  "${item}"`).join(',')}\n]`;
fs.writeFile(fileName, fileContent, (err) => {
    if (err) {
        console.error('Error writing to file:', err);
    } else {
        // console.log(`File "${fileName}" created successfully with wtxins as list.`);
    }
});





const coinbase_tx = (generate_coinbase_tx(wtxns)); //created coinbase transaction





txAll.unshift(littleEndian(doubleHash(coinbase_tx))); // added the coinbase transaction to the txns array

// //write all the txns to a file
const fileName3 = 'txAll.txt';
const fileContent3 = `txns:\n[${txAll.map(item => `\n  "${item}"`).join(',')}\n]`;
fs.writeFile(fileName3, fileContent3, (err) => {
    if (err) {
        console.error('Error writing to file:', err);
    } else {
        // console.log(`File "${fileName2}" created successfully with txins as list.`);
    }
});



const merkleroot = generateMerkleRoot(txAll); // merkle root of the txns array

module.exports = {merkleroot,txAll,coinbase_tx}; //exporting the merkle root and txns array

