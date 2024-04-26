const {concVin,concVout,littleEndian} = require('./functions.js')
const {doubleHash} = require('./hashes.js')

function create_wtxid(tx){
    return doubleHash(littleEndian(tx.version.toString(16).padStart(8,'0'))+ 
            '00'+  //marker
            '01' + //flag
            tx.vin.length.toString(16).padStart(2,'0') +  //number of inputs
            concVin(tx) +  //inputs
            tx.vout.length.toString(16).padStart(2,'0')+  //number of outputs
            concVout(tx) + //outputs
            conc_witness(tx) +  //witness
            littleEndian(tx.locktime.toString(16).padStart(8,'0'))); //locktime
}


function conc_witness(tx) {
  let concstr = '';
  for (const vinEntry of tx.vin) {
      const witness = vinEntry.witness;
      if (witness) { // Check if witness is defined
          concstr += (witness.length).toString(16).padStart(2, '0');
          for (const wit of witness) {
              concstr += (wit.length / 2).toString(16).padStart(2, '0') + wit;
          }
      }
  }
  return concstr;
}

  

module.exports = {create_wtxid}