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
    """
    Encrypts a plaintext string using a stream cipher with a random nonce.
    
    The output is: nonce || ciphertext || MAC
    
    Debug information (nonce, plaintext, ciphertext, and MAC) is printed.
    """
    # Generate a random 16-byte nonce.
    nonce = os.urandom(16)
    plaintext_bytes = plaintext.encode('utf-8')
    
    # Generate a keystream based on the nonce and key.
    keystream = generate_keystream(key, nonce, len(plaintext_bytes))
    
    # Encrypt the plaintext by XORing with the keystream.
    ciphertext = bytes([p ^ k for p, k in zip(plaintext_bytes, keystream)])
    
    # Compute a MAC (message digest) over the ciphertext using HMAC-SHA256 with the key.
    mac = hmac.new(key, ciphertext, hashlib.sha256).digest()
    
    # Print debug information.
    print("\n------------------------------------------------------------------------------------------------------------")
    print("Encryption Debug Info:")
    print("Nonce:", nonce.hex())
    print("Plaintext:", plaintext)
    print("Ciphertext:", ciphertext.hex())
    print("MAC:", mac.hex())
    
    # Return the concatenation: nonce || ciphertext || mac.
    return nonce + ciphertext + mac

def cypher_decrypt(cipher: bytes, key: bytes) -> str:
    """
    Decrypts data that was encrypted using cypher_encrypt.
    
    Expects the input format: nonce (16 bytes) || ciphertext || MAC (32 bytes).
    Prints debug information and verifies the MAC before decryption.
    """
    if len(cipher) < 16 + 32:
        raise ValueError("Input cipher is too short to contain nonce and MAC.")
    
    # Extract nonce, MAC, and ciphertext.
    nonce = cipher[:16]
    mac_provided = cipher[-32:]
    ciphertext = cipher[16:-32]
    
    # Recreate the keystream for the ciphertext.
    keystream = generate_keystream(key, nonce, len(ciphertext))
    
    # Decrypt the ciphertext by XORing with the keystream.
    plaintext_bytes = bytes([c ^ k for c, k in zip(ciphertext, keystream)])
    plaintext = plaintext_bytes.decode('utf-8')
    
    # Compute the MAC over the ciphertext for verification.
    mac_computed = hmac.new(key, ciphertext, hashlib.sha256).digest()
    
    # Print debug information.
    print("\n------------------------------------------------------------------------------------------------------------")
    print("Decryption Debug Info:")
    print("Nonce:", nonce.hex())
    print("Ciphertext:", ciphertext.hex())
    print("Plaintext:", plaintext)
    print("MAC Provided:", mac_provided.hex())
    print("MAC Computed:", mac_computed.hex())
    
    # Verify that the provided MAC matches the computed MAC.
    if not hmac.compare_digest(mac_provided, mac_computed):
        raise ValueError("MAC verification failed! The message's integrity cannot be verified.")
    
    return plaintext

def encrypt_message(message: str, encryption_key: bytes) -> bytes:
    return cypher_encrypt(message, encryption_key)

def decrypt_message(cipher: bytes, encryption_key: bytes) -> str:
    return cypher_decrypt(cipher, encryption_key)

# The secure audit functions.
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