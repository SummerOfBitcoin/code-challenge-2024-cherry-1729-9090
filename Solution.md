<h1>Summer of Bitcoin Code challenge </h1>

## Contents
- [Introduction] (#introduction)
- [Code Explaination] (#code-explaination)
- [Testing](#testing)
- [Challenges faced](#challenges-faced)
- [Future Improvements](#ftimp)
- [References](#references)


## Introduction <a name = "indtroduction"></a>

### Task
 Task is to simulate the mining process of a block, which includes validating and including transactions from a given set of transactions.The repository contains a folder `mempool` which contains JSON files.These files represent individual transactions, some of which may be invalid.



## Code Explaination <a name = "code-explaination"></a>

### File Structure


### Cryptographic and Common functions 


#### Cryptographic functions
- **SHA256**
sha256 uses buffer to convert the given data to bytes and then uses crypto library to create sha256 hash object.
![alt text](<Screenshot 2024-04-25 105659.png>)


- **doublehash**
double hash uses sha256 function internally twice to return the double sha256 of the given data.
![alt text](<Screenshot 2024-04-25 110428.png>)





- **ripemd160**
ripemd160 uses crypto library to return the ripemd160 object and returns the hexadecimal value of the returned object.
![alt text](<Screenshot 2024-04-25 110906.png>)






- **OP_HASH160**
OP_HASH160 uses sha256 and ripemd160 functions internally. It first gives sha256 of given data and then returns ripemd160 of that hash.
![alt text](<Screenshot 2024-04-25 111144.png>)


#### Common functions

- **tohex**
This toHex function converts a given value to its hexadecimal representation and ensures that the result has an even number of digits by padding with a leading zero if necessary.
![alt text](<Screenshot 2024-04-25 111754.png>)


- **littleEndian**
The littleEndian function reverses the byte order of the input data by splitting it into pairs of characters, reversing their order, and then joining them back together.
![alt text](<Screenshot 2024-04-25 113050.png>)




### Serialization 

#### Serialization of transactions
- **concVin**
`./functions/concVin`
![alt text](<Screenshot 2024-04-25 114455.png>)
    Concatenate the vin of all transactions:
    1. Initialize an empty string concatStr.
    2. For each vin in transaction.vin:
        - Convert the txid to `32 bytes little-endian` format in `hexadecimal` and append to concatStr.
        - Convert the vout to `4 bytes little-endian` format in `hexadecimal` and append to concatStr.
        - Calculate the size of scriptsig in bytes and convert it to a `1-byte hexadecimal` value, then append to concatStr.
        - Append the scriptsig to concatStr.
        - Convert the sequence to `4 bytes little-endian` format in `hexadecimal` and append to concatStr.
    3. Return concatStr.


- **concVout**
`./functions/concVout`
![alt text](<Screenshot 2024-04-25 114609.png>)
    Concatenate the vout of all transactions:
    1. Initialize an empty string concatStr.
    2. For each vout in transaction.vout:
        - Convert the value to `8 bytes little-endian` format in `hexadecimal` and append to concatStr.
        - Calculate the size of scriptpubkey in bytes and convert it to a `1-byte hexadecimal` value, then append to concatStr.
        - Append the scriptpubkey to concatStr.
    3. Return concatStr.


- **serializeTransaction**
`./functions/serializeTransaction`
![alt text](<Screenshot 2024-04-25 114702.png>)
    Serialize the transaction:
    1. Initialize an empty string concatStr.
    2. Convert the version to `4` bytes `little-endian format` in `hexadecimal` and append to concatStr.
    3. Convert the number of inputs to a `1-byte` `hexadecimal` value and append to concatStr.
    4. Call `concVin(transaction)` and append the result to concatStr.
    5. Convert the number of outputs to a `1-byte hexadecimal` value and append to concatStr.
    6. Call `concVout(transaction)` and append the result to concatStr.
    7. Convert the locktime to `4 bytes little-endian` format in `hexadecimal` and append to concatStr.
    8. Return the double hash of concatStr.



### File Verification







#### p2wpkh serialization
- **hashPrevouts**
`./p2pwkh/hashPrevouts`
![alt text](<Screenshot 2024-04-25 120620.png>)
    1. Initialize an empty string concStr.
    2. Iterate over each entry vinEntry in transaction.vin.
    3. Convert vinEntry.vout to hexadecimal string voutString padded to 8 characters.
    4. Concatenate the little-endian representation of vinEntry.txid and voutString to concStr.
    5. Return the double hash of concStr.

- **hashSequences**
`./p2pwkh/hashSequences`
![alt text](<Screenshot 2024-04-25 120909.png>)
    1. Initialize an empty string concStr.
    2. Iterate over each entry vinEntry in transaction.vin.
    3. Convert vinEntry.sequence to hexadecimal string sequenceString padded to 8 characters.
    4. Concatenate the little-endian representation of sequenceString to concStr.
    5. Return the double hash of concStr.

- **outpoints**
`./p2pwkh/outpoints`
![alt text](<Screenshot 2024-04-25 121210.png>)
    1. Get the vinEntry at the specified index index from transaction.vin.
    2. Return the concatenation of the little-endian representation of vinEntry.txid and (vinEntry.vout).toString(16) padded to 8 characters.

- **scriptCode**
`./p2pwkh/scriptCode`
![alt text](<Screenshot 2024-04-25 121535.png>)
    1. Get the scriptpubkey from the prevout of the input at index inputIndex in transaction.vin.
    2. Concatenate the required script code elements and return.

- **amount**
`./p2pwkh/amount`
![alt text](<Screenshot 2024-04-25 121845.png>)
    1. Get the value from the prevout of the input at index index in transaction.vin.
    2. Convert it to a little-endian hexadecimal string padded to 16 characters and return.

- **nsequence**
`./p2pwkh/nsequence`
![alt text](<Screenshot 2024-04-25 122159.png>)
    1. Get the sequence from the input at index index in transaction.vin.
    2. Convert it to a little-endian hexadecimal string padded to 8 characters and return.


- **hashOutputs**
`./p2wpkh/hashOutputs`
![alt text](<Screenshot 2024-04-25 122547.png>)
    1. Initialize an empty string concBytes.
    2. Iterate over each entry voutEntry in transaction.vout.
    3. Concatenate little-endian representation of voutEntry.value as a hexadecimal string padded to 16 characters to concBytes.
    4. Convert (voutEntry.scriptpubkey.length / 2) to hexadecimal string padded to 2 characters and concatenate it to concBytes.
    5. Concatenate voutEntry.scriptpubkey to concBytes.
    6. Return the double hash of concBytes.




