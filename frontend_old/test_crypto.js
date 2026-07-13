// // test_crypto.js
// const { clientCrypto } = require('./src/cryptoHelper'); // Adjust path as needed
// const forge = require('node-forge');

// // 1. Generate a mock certificate (so we don't need the real Flask server yet)
// const keys = forge.pki.rsa.generateKeyPair(2048);
// const cert = forge.pki.createCertificate();
// cert.publicKey = keys.publicKey;
// const certPem = forge.pki.certificateToPem(cert);

// // 2. Run the test
// console.log("--- TESTING CRYPTO HELPER ---");
// const sessionKey = clientCrypto.generateSessionKey();
// console.log(`[+] Generated Session Key: ${sessionKey}`);

// const encrypted = clientCrypto.encryptSessionKey(certPem, sessionKey);
// console.log(`[+] Encrypted Hex Payload: ${encrypted.substring(0, 50)}...`);

// if (encrypted.length > 0) {
//     console.log("✅ TEST PASSED: Encryption logic is working!");
// } else {
//     console.log("❌ TEST FAILED: Encryption failed.");
// }

// test_crypto.js
import { clientCrypto } from './src/cryptoHelper.js';
import forge from 'node-forge';

// 1. Generate a mock certificate (so we don't need the real Flask server yet)
// const keys = forge.pki.rsa.generateKeyPair(2048);
// const cert = forge.pki.createCertificate();
// cert.publicKey = keys.publicKey;
// const certPem = forge.pki.certificateToPem(cert);

const keys = forge.pki.rsa.generateKeyPair(2048);
const cert = forge.pki.createCertificate();
cert.publicKey = keys.publicKey;
cert.serialNumber = '01';
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date(new Date().setFullYear(new Date().getFullYear() + 1));
cert.setSubject([{ name: 'commonName', value: 'localhost' }]);
cert.setIssuer([{ name: 'commonName', value: 'localhost' }]);
cert.sign(keys.privateKey); // This was the crucial missing step!
const certPem = forge.pki.certificateToPem(cert);

// 2. Run the test
console.log("--- TESTING CRYPTO HELPER ---");
const sessionKey = clientCrypto.generateSessionKey();
console.log(`[+] Generated Session Key: ${sessionKey}`);

const encrypted = clientCrypto.encryptSessionKey(certPem, sessionKey);
console.log(`[+] Encrypted Hex Payload: ${encrypted.substring(0, 50)}...`);

if (encrypted.length > 0) {
    console.log("✅ TEST PASSED: Encryption logic is working!");
} else {
    console.log("❌ TEST FAILED: Encryption failed.");
}