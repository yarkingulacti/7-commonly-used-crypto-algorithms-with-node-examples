const { generateKeyPairSync } = require("crypto");

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048, // the length of your key in bits
  publicKeyEncoding: {
    type: "spki",
    format: "pem"
  },
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem"
    // Optional passphrase to private key
    // cipher: "aes-256-cbc",
    // passphrase: "top secret"
  }
});

module.exports = { publicKey, privateKey };
