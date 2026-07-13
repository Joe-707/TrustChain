// cryptoHelper.js
// Handles client-side cryptographic math for the TLS Handshake
import forge from 'node-forge';

export const clientCrypto = {
    /**
     * 1. Generate a 16-character Session Key
     * We use a random alphanumeric string so it safely decodes as UTF-8 
     * when it arrives at the Python backend.
     */
    generateSessionKey: () => {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$';
        let key = '';
        for (let i = 0; i < 16; i++) {
            key += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return key;
    },

    /**
     * 2. Encrypt the Session Key for the Handshake
     * Extracts the public key from the server's X.509 PEM certificate
     * and encrypts the session key using RSA-OAEP with SHA-256.
     */
    encryptSessionKey: (serverCertPem, sessionKey) => {
        try {
            console.log("[!] Client: Extracting Public Key from Server Certificate...");

            // Parse the X.509 Certificate to get the Public Key
            const cert = forge.pki.certificateFromPem(serverCertPem);
            const publicKey = cert.publicKey;

            console.log(`[!] Client: Encrypting the secret session key...`);

            // Encrypt using the exact same padding standards as the Python backend
            const encryptedBytes = publicKey.encrypt(sessionKey, 'RSA-OAEP', {
                md: forge.md.sha256.create(),
                mgf1: {
                    md: forge.md.sha256.create()
                }
            });

            // Convert the raw bytes to a Hexadecimal string for transit
            const encryptedHex = forge.util.bytesToHex(encryptedBytes);
            return encryptedHex;

        } catch (error) {
            console.error("[-] Client Encryption Error:", error);
            throw error;
        }
    }
};

