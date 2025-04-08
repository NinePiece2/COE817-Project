import os
import hashlib
import hmac
import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

logger = logging.getLogger(__name__)
logger.propagate = True
BLOCK_SIZE = AES.block_size  # typically 16 bytes

def aes_encrypt(plaintext: str, key: bytes) -> bytes:
    """
    Encrypts a plaintext string using AES in CBC mode.
    
    Process:
    - Pad the plaintext using PKCS7.
    - Generate a random 16-byte IV.
    - Encrypt the padded plaintext with AES-CBC.
    - Compute an HMAC-SHA256 over the ciphertext.
    
    Returns: IV || ciphertext || MAC.
    Debug info is sent to the logger.
    """
    plaintext_bytes = plaintext.encode('utf-8')
    padded_plaintext = pad(plaintext_bytes, BLOCK_SIZE)
    iv = os.urandom(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_plaintext)
    mac = hmac.new(key, ciphertext, hashlib.sha256).digest()

    logger.debug("------------------------------------------------------------------------")
    logger.debug("AES Encryption Debug Info:")
    logger.debug("IV: %s", iv.hex())
    logger.debug("Plaintext: %s", plaintext)
    logger.debug("Padded Plaintext: %s", padded_plaintext.hex())
    logger.debug("Ciphertext: %s", ciphertext.hex())
    logger.debug("MAC: %s", mac.hex())

    return iv + ciphertext + mac

def aes_decrypt(data: bytes, key: bytes) -> str:
    """
    Decrypts data that was encrypted using aes_encrypt.
    
    Expects the input format: IV (16 bytes) || ciphertext || MAC (32 bytes).
    Verifies the MAC before decrypting and unpadding.
    Debug info is sent to the logger.
    """
    if len(data) < BLOCK_SIZE + 32:
        raise ValueError("Input data is too short to contain IV and MAC.")
    
    iv = data[:BLOCK_SIZE]
    mac_provided = data[-32:]
    ciphertext = data[BLOCK_SIZE:-32]
    mac_computed = hmac.new(key, ciphertext, hashlib.sha256).digest()
    
    logger.debug("AES Decryption Debug Info:")
    logger.debug("IV: %s", iv.hex())
    logger.debug("Ciphertext: %s", ciphertext.hex())
    logger.debug("MAC Provided: %s", mac_provided.hex())
    logger.debug("MAC Computed: %s", mac_computed.hex())
    
    if not hmac.compare_digest(mac_provided, mac_computed):
        raise ValueError("MAC verification failed! The message's integrity cannot be verified.")
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext_bytes = unpad(padded_plaintext, BLOCK_SIZE)
    plaintext = plaintext_bytes.decode('utf-8')
    
    logger.debug("Decrypted Plaintext: %s", plaintext)
    
    return plaintext

def encrypt_message(message: str, encryption_key: bytes) -> bytes:
    return aes_encrypt(message, encryption_key)

def decrypt_message(data: bytes, encryption_key: bytes) -> str:
    return aes_decrypt(data, encryption_key)

#  Secure audit functions
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