"""
aes_engine.py - AES-128 CBC Symmetric Encryption Engine
Author: Joe
Description: AES-128 encryption in CBC mode for bulk data encryption
             Uses session key from Austin's handshake
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64
import hashlib
import hmac


class AESEngine:
    """
    AES-128 CBC encryption engine for bulk data encryption
    Designed to work with session keys from the handshake
    """

    def __init__(self, session_key=None):
        """
        Initialize the AES engine with a session key

        Args:
            session_key: bytes or str - the session key from handshake
                          If string, it will be encoded to bytes
                          If None, a random key will be generated
        """
        if session_key:
            # If session_key is a string, convert to bytes
            if isinstance(session_key, str):
                session_key = session_key.encode('utf-8')

            # Ensure key is exactly 16 bytes for AES-128
            # Use SHA-256 to derive a 16-byte key from any length input
            if len(session_key) != 16:
                # Hash to 32 bytes, then take first 16
                hashed = hashlib.sha256(session_key).digest()
                self.key = hashed[:16]  # AES-128 uses 16 bytes
            else:
                self.key = session_key
        else:
            # Generate a random 16-byte key for AES-128
            self.key = os.urandom(16)

        self.block_size = 16  # AES block size in bytes

    def encrypt(self, plaintext):
        """
        Encrypt a message using AES-128 CBC with PKCS7 padding

        Args:
            plaintext: str or bytes - the message to encrypt

        Returns:
            dict: {
                'ciphertext': base64 encoded string,
                'iv': base64 encoded string
            }
        """
        # Convert to bytes if string
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        # Generate random Initialization Vector (IV)
        iv = os.urandom(self.block_size)

        # Create AES-128 CBC cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        # Apply PKCS7 padding
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        # Encrypt
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # NEW: Generate HMAC Signature (Encrypt-then-MAC)
        # We sign the combination of the IV and the ciphertext
        mac_data = iv + ciphertext
        signature = hmac.new(self.key, mac_data, hashlib.sha256).digest()

        # Return as Base64 for JSON transmission
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'hmac_signature': base64.b64encode(signature).decode('utf-8') # NEW
        }

        # Return as Base64 for JSON transmission
        #return {
           # 'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            #'iv': base64.b64encode(iv).decode('utf-8')
        #}

    def decrypt(self, ciphertext_b64, iv_b64, hmac_b64=None):

        """
        Decrypt an AES-128 CBC encrypted message

        Args:
            ciphertext_b64: str - base64 encoded ciphertext
            iv_b64: str - base64 encoded initialization vector
            hmac_b64: str - optional base64 encoded HMAC signature

        Returns:
            str: decrypted plaintext
        """

        # Decode from Base64
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)

        # Integrity Check Verification
        if hmac_b64:
            received_signature = base64.b64decode(hmac_b64)
            mac_data = iv + ciphertext
            expected_signature = hmac.new(self.key, mac_data, hashlib.sha256).digest()
            
            if not hmac.compare_digest(expected_signature, received_signature):
                raise ValueError("INTEGRITY COMPROMISED: The payload was tampered with in transit!")
            

        # Validate IV length
        if len(iv) != self.block_size:
            raise ValueError(f"IV must be {self.block_size} bytes")

        # Create AES-128 CBC cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        # Decrypt
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext.decode('utf-8')

    def encrypt_to_json(self, plaintext):
        """Convenience method: encrypt and return JSON-serializable dict"""
        return self.encrypt(plaintext)

    def decrypt_from_json(self, encrypted_data):
        """Convenience method: decrypt from JSON-serializable dict"""
        if isinstance(encrypted_data, dict):
            return self.decrypt(
                encrypted_data['ciphertext'],
                encrypted_data['iv'],
                encrypted_data.get('hmac_signature')
            )
        else:
            raise ValueError("Expected dict with 'ciphertext' and 'iv' keys")

    def get_key_hex(self):
        """Get the session key as hexadecimal string"""
        return self.key.hex()

    def get_key_b64(self):
        """Get the session key as base64 string"""
        return base64.b64encode(self.key).decode('utf-8')


# ============================================
# TESTING SECTION
# ============================================

def test_aes_engine():
    """Test the AES engine with various scenarios"""
    print("=" * 60)
    print("🔐 Testing AES-128 CBC Encryption Engine")
    print("=" * 60)

    # Test 1: Random session key
    print("\n📝 Test 1: Auto-generated session key")
    aes = AESEngine()
    print(f"   Generated key (hex): {aes.get_key_hex()[:16]}...")

    # Test 2: Specific session key (simulating handshake)
    print("\n📝 Test 2: Using session key from handshake")
    session_key = b"SharedSecretKey!"  # 16 bytes exactly
    aes = AESEngine(session_key)
    print(f"   Key (hex): {aes.get_key_hex()}")

    # Test 3: Encrypt/Decrypt with various messages
    test_messages = [
        "Hello, this is a secure message!",
        "Short",
        "This message exceeds the AES block size of 16 bytes to test PKCS7 padding.",
        "Special chars: !@#$%^&*()_+",
        "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ]

    print(f"\n📝 Test 3: Encrypting {len(test_messages)} messages...")

    for i, message in enumerate(test_messages, 1):
        print(f"\n   Message {i}: '{message[:30]}{'...' if len(message) > 30 else ''}'")

        # Encrypt
        encrypted = aes.encrypt(message)

        print(f"   🔒 Ciphertext (first 30 chars): {encrypted['ciphertext'][:30]}...")
        print(f"   🔑 IV (first 20 chars): {encrypted['iv'][:20]}...")
        print(f"   🛡️ HMAC Signature (first 30 chars): {encrypted['hmac_signature'][:30]}...")

        # Decrypt
        decrypted = aes.decrypt(encrypted['ciphertext'], encrypted['iv'], encrypted.get('hmac_signature'))
        print(f"   📄 Decrypted: {decrypted}")

        # Verify
        assert message == decrypted, "❌ Test failed!"
        print("   ✅ PASSED")

    # Test 4: Different keys produce different ciphertexts
    print("\n📝 Test 4: Different keys produce different ciphertexts")
    aes1 = AESEngine(b"KeyNumberOne1234")
    aes2 = AESEngine(b"KeyNumberTwo1234")

    plaintext = "Same message"
    encrypted1 = aes1.encrypt(plaintext)
    encrypted2 = aes2.encrypt(plaintext)

    print(f"   Ciphertext 1: {encrypted1['ciphertext'][:30]}...")
    print(f"   Ciphertext 2: {encrypted2['ciphertext'][:30]}...")

    if encrypted1['ciphertext'] != encrypted2['ciphertext']:
        print("   ✅ Different keys produce different ciphertexts")
    else:
        print("   ❌ Same ciphertext - something is wrong!")

    print("\n" + "=" * 60)
    print("✅ ALL TESTS PASSED! AES engine is ready.")
    print("=" * 60)


if __name__ == '__main__':
    test_aes_engine()