// apiService.js
// Handles all HTTP communication between the React frontend and the Flask backend

const API_BASE_URL = 'http://127.0.0.1:5000/api';

export const cryptoAPI = {
    /**
     * 1. Initialize PKI
     * Fetches the Root CA and Server Certificate from the backend.
     */
    initPKI: async () => {
        try {
            const response = await fetch(`${API_BASE_URL}/pki/init`);
            const data = await response.json();
            if (!response.ok) throw new Error(data.message);
            return data.data; // Returns { ca_certificate, server_certificate, server_private_key }
        } catch (error) {
            console.error("[-] PKI Init Error:", error);
            throw error;
        }
    },

    /**
     * 2. Execute TLS Handshake
     * Sends the encrypted session key to the server to establish the symmetric AES tunnel.
     */
    sendHandshake: async (serverPrivateKey, encryptedSessionKeyHex) => {
        try {
            const response = await fetch(`${API_BASE_URL}/tls/handshake`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    server_private_key: serverPrivateKey,
                    encrypted_session_key: encryptedSessionKeyHex
                })
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.message);
            return data.data;
        } catch (error) {
            console.error("[-] Handshake Error:", error);
            throw error;
        }
    },

    /**
     * 3. Send a Message (Triggers backend AES Encryption + HMAC)
     */
    sendMessage: async (messageText) => {
        try {
            const response = await fetch(`${API_BASE_URL}/tls/send-message`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    mode: 'encrypted',
                    message: messageText
                })
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.message);
            return data.data; // Returns { ciphertext, iv, hmac_signature, etc. }
        } catch (error) {
            console.error("[-] Send Message Error:", error);
            throw error;
        }
    },

    /**
     * 4. Decrypt a Message (Triggers backend AES Decryption + HMAC Validation)
     */
    decryptMessage: async (ciphertext, iv, hmacSignature) => {
        try {
            const response = await fetch(`${API_BASE_URL}/tls/decrypt`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ciphertext: ciphertext,
                    iv: iv,
                    hmac_signature: hmacSignature
                })
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.message);
            return data.data; // Returns { plaintext }
        } catch (error) {
            console.error("[-] Decrypt Message Error:", error);
            throw error;
        }
    }
};