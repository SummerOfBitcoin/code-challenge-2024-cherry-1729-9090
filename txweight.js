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





