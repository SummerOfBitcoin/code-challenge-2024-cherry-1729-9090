// function calculateTransactionWeight(tx) {
//     let witness_bytes = 0;
//   let non_witness_bytes = 0;

//   let tx_type = tx['vin'].every(vin => 'scriptsig' in vin) ? "LEGACY" : "SEGWIT";

//   if (tx_type === "LEGACY") {
//       // VERSION
//       non_witness_bytes += 4;

//       if (tx['vin'].length >= 50) {
//           // throw new Error("Too many inputs");
//           return false;
//       }

//       // INPUT COUNT
//       non_witness_bytes += 1;

//       // INPUTS
//       for (let input of tx['vin']) {
//           // TXID
//           non_witness_bytes += 32;

//           // VOUT
//           non_witness_bytes += 4;

//           // SCRIPTSIG
//           let script_sig = Buffer.from(input['scriptsig'] || '', 'hex');
//           non_witness_bytes += 1 + (script_sig.length/2);

//           // SEQUENCE
//           non_witness_bytes += 4;
//       }

//       if (tx['vout'].length >= 50) {
//           // throw new Error("Too many outputs");
//           return false;
//       }

//       // OUTPUT COUNT
//       non_witness_bytes += 1;

//       // OUTPUTS
//       for (let output of tx['vout']) {
//           // VALUE
//           non_witness_bytes += 8;

//           // SCRIPTPUBKEY
//           let scriptpubkey = Buffer.from(output['scriptpubkey'], 'hex');
//           non_witness_bytes += 1 + (scriptpubkey.length/2);
//       }

//       // LOCKTIME
//       non_witness_bytes += 4;

//   } else {
//       // VERSION
//       non_witness_bytes += 4;

//       // MARKER and FLAG (witness data)
//       witness_bytes += 2;

//       if (tx['vin'].length >= 50) {
//           // throw new Error("Too many inputs");
//           return false;
//       }

//       // INPUT COUNT
//       non_witness_bytes += 1;

//       // INPUTS
//       for (let input of tx['vin']) {
//           // TXID and VOUT
//           non_witness_bytes += 32 + 4;

//           // SCRIPTSIG (if any)
//           let script_sig = Buffer.from(input['scriptsig'] || '', 'hex');
//           non_witness_bytes += 1 + (script_sig.length / 2);

//           // SEQUENCE
//           non_witness_bytes += 4;
//       }

//       if (tx['vout'].length >= 255) {
//           // throw new Error("Too many outputs");
//           return false;
//       }

//       // OUTPUT COUNT
//       non_witness_bytes += 1;

//       // OUTPUTS
//       for (let output of tx['vout']) {
//           // VALUE and SCRIPTPUBKEY
//           let scriptpubkey = Buffer.from(output['scriptpubkey'], 'hex');
//           non_witness_bytes += 8 + 1 + (scriptpubkey.length / 2);
//       }

//       // WITNESS DATA
//       for (let input of tx['vin']) {
//           let witness = input['witness'] || [];
//           for (let item of witness) {
//               let item_bytes = Buffer.from(item, 'hex');
//               witness_bytes += 1 + (item_bytes.length / 2);
//           }
//       }

//       // LOCKTIME
//       non_witness_bytes += 4;
//   }

//   // Calculate the total weight of the transaction
//   let tx_weight = (non_witness_bytes * 4) + witness_bytes;

//   return tx_weight;
// }


function calculateTransactionWeight(tx) {
    let tx_weight = 0;
    let segwit_wt = 0;

    // Check if the transaction is segwit or not
    let tx_type = "SEGWIT";

    // Determining the type of the transaction
    if (tx.vin.some((e) => e.witness === undefined)) {
        tx_type = "LEGACY";
    }

    // VERSION
    tx_weight += 4;

    if (tx.vin.length >= 50) {
        // throw new Error("Too many inputs");
        return false;
    }

    // INPUT COUNT
    tx_weight += 1;

    // INPUTS
    for (let input of tx.vin) {
        // TXID and VOUT
        tx_weight += 32 + 4;

        // SCRIPTSIG
        let script_sig = Buffer.from(input['scriptsig'] || '', 'hex');
        tx_weight += 1 + (script_sig.length / 2);

        // SEQUENCE
        tx_weight += 4;
    }

    if (tx.vout.length >= 50) {
        // throw new Error("Too many outputs");
        return false;
    }

    // OUTPUT COUNT
    tx_weight += 1;

    // OUTPUTS
    for (let output of tx.vout) {
        // VALUE and SCRIPTPUBKEY
        let scriptpubkey = Buffer.from(output['scriptpubkey'], 'hex');
        tx_weight += 8 + 1 + (scriptpubkey.length / 2);
    }

    // LOCKTIME
    tx_weight += 4;

    if (tx_type === "SEGWIT") {
        // MARKER and FLAG (witness data)
        segwit_wt += 2;

        // WITNESS DATA
        for (let input of tx.vin) {
            let witness = input['witness'] || [];
            for (let item of witness) {
                let item_bytes = Buffer.from(item, 'hex');
                segwit_wt += 1 + (item_bytes.length / 2);
            }
        }
    }

    // Calculate the total weight of the transaction
    tx_weight = tx_weight * 4 + segwit_wt;

    return tx_weight;
}

module.exports = { calculateTransactionWeight };


module.exports = {calculateTransactionWeight}





