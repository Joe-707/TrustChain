from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import binascii

def decrypt_session_key(server_private_key_pem, encrypted_session_key_hex):
    """
    Simulates the server receiving an encrypted session key from the client.
    Uses the server's RSA private key to decrypt it via OAEP padding.
    """
    print("[*] Server: Loading Private Key...")
    # 1. Load the private key from the raw PEM string
    private_key = serialization.load_pem_private_key(
        server_private_key_pem.encode('utf-8'),
        password=None
    )

    print("[*] Server: Decrypting client payload...")
    # 2. Convert the incoming hex string back into raw bytes
    encrypted_bytes = binascii.unhexlify(encrypted_session_key_hex)

    # 3. Decrypt using the exact same padding standards the client used to encrypt
    decrypted_key = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("[+] Server: Successfully extracted Client's Session Key!")
    return decrypted_key.decode('utf-8')


# --- SELF-TEST BLOCK ---
# To prove this works, we need a quick function to simulate what React will do
def simulate_react_client_encryption(server_cert_pem, secret_session_key):
    from cryptography import x509
    
    print("\n[!] Client: Extracting Public Key from Server Certificate...")
    cert = x509.load_pem_x509_certificate(server_cert_pem.encode('utf-8'))
    public_key = cert.public_key()
    
    print(f"[!] Client: Encrypting the secret key: '{secret_session_key}'")
    encrypted_bytes = public_key.encrypt(
        secret_session_key.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return binascii.hexlify(encrypted_bytes).decode('utf-8')


if __name__ == "__main__":
    from pki_engine import generate_root_ca, sign_server_certificate
    
    print("--- STARTING HANDSHAKE ENGINE SELF-TEST ---")
    # 1. Spin up the keys (borrowing from your pki_engine)
    ca_key, ca_cert, ca_key_pem = generate_root_ca()
    srv_key_pem, srv_cert_pem = sign_server_certificate(ca_key, ca_cert)
    
    # 2. Client Simulation (React generates a 16-character AES key)
    my_secret_key = "SuperSecretKey12"
    encrypted_hex_payload = simulate_react_client_encryption(srv_cert_pem.decode('utf-8'), my_secret_key)
    
    print(f"\n[INTERCEPT] Encrypted Payload moving over the wire:\n{encrypted_hex_payload}\n")
    
    # 3. Server Execution (Your Handshake Engine)
    recovered_key = decrypt_session_key(srv_key_pem.decode('utf-8'), encrypted_hex_payload)
    
    print(f"\n[+] FINAL VERIFICATION: Recovered key is '{recovered_key}'")
    if my_secret_key == recovered_key:
        print("[+] HANDSHAKE SUCCESS: The math matches perfectly.\n")