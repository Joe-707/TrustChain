import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_root_ca():
    """
    Generates a 2048-bit RSA Private Key and a Self-Signed Root Certificate.
    """
    # 1. GENERATE PRIVATE KEY: This 2048-bit RSA key is the CA's ultimate secret.
    # The public exponent 65537 is a standard prime number that balances security and mathematical speed.
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # 2. DEFINE IDENTITY: Create an X.509 naming structure.
    # Since this is a Root CA, the "Subject" (who owns it) and "Issuer" (who signed it) are identical.
    identity = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"KE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"TrustChain Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"TrustChain Local Root CA"),
    ])

    # 3. BUILD THE CERTIFICATE: Assemble the raw attributes and enforce modern strictness.
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(identity)
        .issuer_name(identity)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650)) # Valid for 10 years
        # CRITICAL EXTENSION: Explicitly label this key as a CA so Python trusts it to sign things
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        # CRITICAL EXTENSION: Limit its permissions strictly to signing certificates and CRLs
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False
            ),
            critical=True
        )
        # Sign the entire certificate using its own private key and a secure SHA-256 hash
        .sign(ca_private_key, hashes.SHA256())
    )

    # 4. SERIALIZE TO STRING: Convert raw bytes into readable PEM (Base64 ASCII) strings for the UI
    ca_key_pem = ca_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)

    return ca_private_key, ca_cert_pem, ca_key_pem


def sign_server_certificate(ca_private_key, ca_cert_pem):
    """
    Generates a server keypair and signs it using the provided Root CA private key.
    """
    # 1. GENERATE SERVER KEY: The web server (localhost) gets its own unique 2048-bit RSA key.
    server_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # 2. DEFINE IDENTITIES: Parse the CA's identity from its PEM data to act as the Issuer.
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"KE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"TrustChain Local Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])

    # 3. MINT SERVER CERTIFICATE: Construct the identity token for the web server.
    now = datetime.datetime.now(datetime.timezone.utc)
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_cert.subject) # The CA's Subject becomes the Server's Issuer
        .public_key(server_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365)) # Valid for 1 year
        # CRITICAL EXTENSION: Explicitly mark this as an end-entity server cert (NOT a CA)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        # CRITICAL EXTENSION: Allow this key to be used for encrypting handshakes (Key Encipherment)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False
            ),
            critical=True
        )
        # Mathematically link the server certificate to the Root CA by signing it with the CA's private key
        .sign(ca_private_key, hashes.SHA256())
    )

    # 4. SERIALIZE TO STRING
    server_key_pem = server_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    server_cert_pem = server_cert.public_bytes(serialization.Encoding.PEM)

    return server_key_pem, server_cert_pem


# Local Verification Test Block
if __name__ == "__main__":
    print("--- STARTING CRYPTOGRAPHIC ENGINE SELF-TEST ---")
    ca_key, ca_cert, ca_key_pem = generate_root_ca()
    print("[+] Root CA Cert successfully generated.")
    
    srv_key_pem, srv_cert_pem = sign_server_certificate(ca_key, ca_cert)
    print("[+] Server Certificate successfully signed by Root CA.")
    
    print("\n--- SAMPLE OUTPUT (SERVER CERTIFICATE PEM) ---")
    print(srv_cert_pem.decode('utf-8')[:300] + "\n...[TRUNCATED BASE64 CRYPTO DATA]...\n")