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
    try:
        # 1. Capture the incoming JSON payload from React
        data = request.json
        server_key_pem = data.get('server_private_key')
        encrypted_hex = data.get('encrypted_session_key')

        if not server_key_pem or not encrypted_hex:
            return jsonify({
                "status": "error", 
                "message": "Missing server key or encrypted payload in request."
            }), 400

        # 2. Pass the data into your Handshake Engine
        decrypted_key = decrypt_session_key(server_key_pem, encrypted_hex)

        # 3. Return the successful result
        return jsonify({
            "status": "success",
            "message": "Handshake successful. Symmetric session key established.",
            "data": {
                "session_key": decrypted_key
            }
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Handshake failed: {str(e)}"
        }), 500


if __name__ == '__main__':
    print("[*] Starting TrustChain API Server on port 5000...")
    app.run(debug=True, host='127.0.0.1', port=5000)