import os
import hashlib
import hmac

def generate_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Generates a keystream of the desired length using SHA-256 in counter mode."""
    keystream = b""
    counter = 0
    while len(keystream) < length:
        counter_bytes = counter.to_bytes(4, byteorder="big")
        block = hashlib.sha256(nonce + key + counter_bytes).digest()
        keystream += block
        counter += 1
    return keystream[:length]

def cypher_encrypt(plaintext: str, key: bytes) -> bytes:
    """Encrypts a plaintext string using a stream cipher with a random nonce.
    
    The output is: nonce || ciphertext.
    Debug information (nonce, plaintext, ciphertext, and MAC) is printed.
    """
    # Generate a random 16-byte nonce.
    nonce = os.urandom(16)
    plaintext_bytes = plaintext.encode('utf-8')
    # Generate a keystream based on the nonce and key.
    keystream = generate_keystream(key, nonce, len(plaintext_bytes))
    # Encrypt the plaintext by XORing with the keystream.
    ciphertext = bytes([p ^ k for p, k in zip(plaintext_bytes, keystream)])
    # Compute a MAC over the ciphertext (using HMAC-SHA256 with the key).
    mac = hmac.new(key, ciphertext, hashlib.sha256).digest()
    
    # Print debug information.
    print("\n------------------------------------------------------------------------------------------------------------")
    print("Encryption Debug Info:")
    print("Nonce:", nonce.hex())
    print("Plaintext:", plaintext)
    print("Ciphertext:", ciphertext.hex())
    print("MAC:", mac.hex())
    
    # Return the nonce concatenated with the ciphertext.
    return nonce + ciphertext

def cypher_decrypt(cipher: bytes, key: bytes) -> str:
    """Decrypts data that was encrypted using cypher_encrypt.
    
    Expects the first 16 bytes to be the nonce. Prints debug information.
    """
    # Extract nonce (first 16 bytes) and ciphertext.
    nonce = cipher[:16]
    ciphertext = cipher[16:]
    # Recreate the keystream for the ciphertext.
    keystream = generate_keystream(key, nonce, len(ciphertext))
    # Decrypt the ciphertext by XORing with the keystream.
    plaintext_bytes = bytes([c ^ k for c, k in zip(ciphertext, keystream)])
    plaintext = plaintext_bytes.decode('utf-8')
    # Compute a MAC over the ciphertext for debug purposes.
    mac = hmac.new(key, ciphertext, hashlib.sha256).digest()
    
    # Print debug information.
    print("\nDecryption Debug Info:")
    print("Nonce:", nonce.hex())
    print("Ciphertext:", ciphertext.hex())
    print("Plaintext:", plaintext)
    print("MAC:", mac.hex())

    return plaintext

# These are the new encryption and decryption functions that will be used by your client and server.
def encrypt_message(message: str, encryption_key: bytes) -> bytes:
    return cypher_encrypt(message, encryption_key)

def decrypt_message(cipher: bytes, encryption_key: bytes) -> str:
    return cypher_decrypt(cipher, encryption_key)

# The secure audit functions remain available (they use a simple XOR-based method).
def secure_audit_key():
    SECRET_KEY = b"audit_secret_key"
    return hashlib.sha256(SECRET_KEY).digest()

def secure_encrypt_audit(text: str) -> str:
    key = secure_audit_key()
    message_bytes = text.encode('utf-8')
    cipher_bytes = bytes([m ^ key[i % len(key)] for i, m in enumerate(message_bytes)])
    return cipher_bytes.hex()

def secure_decrypt_audit(cipher_hex: str) -> str:
    key = secure_audit_key()
    cipher_bytes = bytes.fromhex(cipher_hex)
    message_bytes = bytes([c ^ key[i % len(key)] for i, c in enumerate(cipher_bytes)])
    return message_bytes.decode('utf-8')