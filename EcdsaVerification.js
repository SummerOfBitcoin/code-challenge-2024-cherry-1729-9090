const crypto = require('crypto');
const EC = require('elliptic').ec;
const ecdsa = new EC('secp256k1');
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
    //checking
  }

  // function to verify the ECDSA signature
  function verifyECDSASignature(publicKeyHex, signatureHex, messageHex) {
    const ecdsa = new EC("secp256k1");
    const key = ecdsa.keyFromPublic(publicKeyHex, "hex");
    const signature = parseDER(signatureHex);
    const isValid = key.verify(messageHex, signature);
    return isValid;
  }
  

  module.exports = { verifyECDSASignature }
