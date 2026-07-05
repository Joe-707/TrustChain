# from flask import Flask, jsonify
# from flask_cors import CORS
# from pki_engine import generate_root_ca, sign_server_certificate

# app = Flask(__name__)
# # Enable CORS so the React frontend (which will run on a different port) can talk to this API
# CORS(app)

# @app.route('/api/pki/init', methods=['GET'])
# def init_pki():
#     """
#     API Endpoint to initialize the entire PKI ecosystem.
#     Returns the Root CA and the Server Certificate as JSON strings.
#     """
#     try:
#         # 1. Generate the Root CA
#         ca_private_key, ca_cert_pem, ca_key_pem = generate_root_ca()
        
#         # 2. Use the Root CA to sign a new server certificate
#         server_key_pem, server_cert_pem = sign_server_certificate(ca_private_key, ca_cert_pem)
        
#         # 3. Package the PEM strings into a JSON response
#         return jsonify({
#             "status": "success",
#             "message": "PKI initialized successfully.",
#             "data": {
#                 "ca_certificate": ca_cert_pem.decode('utf-8'),
#                 "server_certificate": server_cert_pem.decode('utf-8'),
#                 "server_private_key": server_key_pem.decode('utf-8')
#                 # Note: We NEVER expose the Root CA private key over an API in the real world, 
#                 # so we intentionally leave it out of this payload!
#             }
#         }), 200

#     except Exception as e:
#         return jsonify({
#             "status": "error",
#             "message": str(e)
#         }), 500

# if __name__ == '__main__':
#     print("[*] Starting TrustChain API Server on port 5000...")
#     app.run(debug=True, host='127.0.0.1', port=5000)

from flask import Flask, jsonify, request
from flask_cors import CORS
from pki_engine import generate_root_ca, sign_server_certificate
from handshake_engine import decrypt_session_key  # NEW: Importing your handshake logic
from aes_engine import AESEngine


app = Flask(__name__)
CORS(app)

@app.route('/api/pki/init', methods=['GET'])
def init_pki():
    """
    API Endpoint to initialize the entire PKI ecosystem.
    """
    try:
        ca_private_key, ca_cert_pem, ca_key_pem = generate_root_ca()
        server_key_pem, server_cert_pem = sign_server_certificate(ca_private_key, ca_cert_pem)
        
        return jsonify({
            "status": "success",
            "message": "PKI initialized successfully.",
            "data": {
                "ca_certificate": ca_cert_pem.decode('utf-8'),
                "server_certificate": server_cert_pem.decode('utf-8'),
                "server_private_key": server_key_pem.decode('utf-8')
            }
        }), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# NEW ENDPOINT: The TLS Handshake
@app.route('/api/tls/handshake', methods=['POST'])
def tls_handshake():
    """
    API Endpoint simulating the server receiving the client's pre-master secret.
    The frontend sends the encrypted payload, the server decrypts it.
    """
    global session_key, aes_engine

    try:
        # 1. Capture the incoming JSON payload from React
        data = request.json
        server_key_pem = data.get('server_private_key')
        encrypted_hex = data.get('encrypted_session_key')

        if not server_key_pem or not encrypted_hex:
            return jsonify({
                "status": "error",
                "message": "Missing server key or encrypted payload in request.",
            }), 400

        # 2. Pass the data into Austin's Handshake Engine
        decrypted_key = decrypt_session_key(server_key_pem, encrypted_hex)

        # ============================================
        # JOE'S PART: Initialize AES engine with session key
        # ============================================
        session_key = decrypted_key
        aes_engine = AESEngine(session_key)

        print(f"[*] Joe: AES engine initialized with session key")

        # 3. Return the successful result
        return jsonify({
            "status": "success",
            "message": "Handshake successful. Symmetric session key established.",
            "data": {
                "session_key": decrypted_key,
                "aes_algorithm": "AES-128-CBC",
                "aes_status": "initialized"
            }
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Handshake failed: {str(e)}"
        }), 500

    # ============================================
    # JOE'S AES ENCRYPTION ENDPOINTS
    # ============================================

    # Import your AES engine (add at the top of the file with other imports)
    # from aes_engine import AESEngine

    # Global state for AES
    aes_engine = None
    session_key = None

    @app.route('/api/tls/send-message', methods=['POST'])
    def send_message():
        """
        YOUR ENDPOINT: Send encrypted or plaintext message
        Uses AES-128 CBC for bulk data encryption
        """
        global aes_engine

        try:
            data = request.json
            if not data:
                return jsonify({
                    "status": "error",
                    "message": "No data provided"
                }), 400

            mode = data.get('mode', 'plain')
            message = data.get('message', '')

            if mode == 'encrypted':
                # Check if AES engine is initialized
                if not aes_engine:
                    return jsonify({
                        "status": "error",
                        "message": "No session key established. Call /api/tls/handshake first.",
                        "hint": "Call /api/tls/handshake first"
                    }), 400

                # YOUR AES ENGINE: Encrypt the message
                encrypted_data = aes_engine.encrypt(message)

                return jsonify({
                    "status": "success",
                    "message": "Message encrypted with AES-128-CBC",
                    "data": {
                        'mode': 'encrypted',
                        'ciphertext': encrypted_data['ciphertext'],
                        'iv': encrypted_data['iv'],
                        'original_length': len(message),
                        'encrypted_length': len(encrypted_data['ciphertext']),
                        'algorithm': 'AES-128-CBC'
                    }
                }), 200
            else:
                # Plaintext mode (HTTP)
                return jsonify({
                    "status": "success",
                    "message": "Plaintext message sent (no encryption)",
                    "data": {
                        'mode': 'plain',
                        'content': message,
                        'length': len(message)
                    }
                }), 200

        except Exception as e:
            return jsonify({
                "status": "error",
                "message": f"Failed to send message: {str(e)}"
            }), 500

    @app.route('/api/tls/decrypt', methods=['POST'])
    def decrypt_message():
        """
        YOUR ENDPOINT: Decrypt a message
        Uses AES-128 CBC with the established session key
        """
        global aes_engine

        try:
            data = request.json
            if not data:
                return jsonify({
                    "status": "error",
                    "message": "No data provided"
                }), 400

            # Check if AES engine is initialized
            if not aes_engine:
                return jsonify({
                    "status": "error",
                    "message": "No session key established. Call /api/tls/handshake first."
                }), 400

            ciphertext = data.get('ciphertext')
            iv = data.get('iv')

            if not ciphertext or not iv:
                return jsonify({
                    "status": "error",
                    "message": "Missing ciphertext or IV"
                }), 400

            # YOUR AES ENGINE: Decrypt the message
            plaintext = aes_engine.decrypt(ciphertext, iv)

            return jsonify({
                "status": "success",
                "message": "Message decrypted successfully",
                "data": {
                    'plaintext': plaintext,
                    'length': len(plaintext),
                    'algorithm': 'AES-128-CBC'
                }
            }), 200

        except Exception as e:
            return jsonify({
                "status": "error",
                "message": f"Decryption failed: {str(e)}"
            }), 500

    @app.route('/api/tls/session-status', methods=['GET'])
    def session_status():
        """
        YOUR ENDPOINT: Check if session key and AES engine are ready
        """
        global aes_engine

        return jsonify({
            "status": "success",
            "message": "Session status retrieved",
            "data": {
                'has_session_key': aes_engine is not None,
                'session_active': aes_engine is not None,
                'algorithm': 'AES-128-CBC' if aes_engine else None,
                'session_key': session_key if session_key else None
            }
        }), 200

    @app.route('/api/tls/encryption-info', methods=['GET'])
    def encryption_info():
        """
        YOUR ENDPOINT: Get info about the AES encryption
        """
        global aes_engine

        if not aes_engine:
            return jsonify({
                "status": "error",
                "message": "No session key established. Call /api/tls/handshake first."
            }), 400

        return jsonify({
            "status": "success",
            "message": "Encryption info retrieved",
            "data": {
                'algorithm': 'AES-128-CBC',
                'key_length': '128 bits',
                'block_size': '128 bits',
                'padding': 'PKCS7',
                'key_hex': aes_engine.get_key_hex()
            }
        }), 200


if __name__ == '__main__':
    print("[*] Starting TrustChain API Server on port 5000...")
    app.run(debug=True, host='127.0.0.1', port=5000)