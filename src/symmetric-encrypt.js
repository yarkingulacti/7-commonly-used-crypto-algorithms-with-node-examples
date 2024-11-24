const { createCipheriv, randomBytes, createDecipheriv } = require("crypto");

/// Cipher

const message = "i like turtles";
const key = randomBytes(32);
const iv = randomBytes(16); // Initialization vector, this will randomize the encryption

const cipher = createCipheriv("aes256", key, iv);

/// Encypt

const encryptedMessage =
  cipher.update(message, "utf8", "hex") + cipher.final("hex");

/// Decypt

const decipher = createDecipheriv("aes256", key, iv);
const descryptedMessage =
  decipher.update(encryptedMessage, "hex", "utf-8") + decipher.final("utf8");

console.log(`Deciphered: ${descryptedMessage.toString("utf-8")}`);
