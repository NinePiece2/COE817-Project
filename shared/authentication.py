import hashlib
import os
import hmac
import logging
from Crypto.Cipher import AES

logger = logging.getLogger(__name__)
logger.propagate = True
# Pre-shared key between client and server
SHARED_KEY = b'shared_secret_key_123'

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)  # 16-byte salt
    pwd_hash = hashlib.sha256(salt + password.encode()).digest()
    return salt.hex() + pwd_hash.hex()

def verify_password(password, stored_hash):
    salt = bytes.fromhex(stored_hash[:32])
    expected_hash = stored_hash[32:]
    pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
    return hmac.compare_digest(pwd_hash, expected_hash)

def generate_master_secret():
    return os.urandom(32)  # 256-bit master secret

def generate_mac(message, key):
    return hmac.new(key, message, hashlib.sha256).digest()

def verify_mac(message, mac, key):
    expected_mac = hmac.new(key, message, hashlib.sha256).digest()
    logger.debug("Expected MAC: %s - Actual MAC: %s", expected_mac.hex(), mac.hex())
    return hmac.compare_digest(mac, expected_mac)

def derive_keys(master_secret):
    encryption_key = hashlib.sha256(master_secret + b'encryption').digest()
    mac_key = hashlib.sha256(master_secret + b'mac').digest()
    logger.debug("Derived Encryption Key: %s", encryption_key.hex())
    return encryption_key, mac_key

def server_authenticated_key_distribution(client_nonce):
    """
    Generates a master secret and encrypts it using AES in CBC mode with a key derived from SHARED_KEY.
    It then computes a MAC (using HMAC-SHA256) over (client_nonce || master_secret).
    
    Returns a tuple (encrypted_master, mac) where:
      - encrypted_master = IV (16 bytes) || AES-CBC(master_secret)
      - mac is computed over (client_nonce || master_secret) using SHARED_KEY.
    """
    master_secret = generate_master_secret()
    message = client_nonce + master_secret
    mac = generate_mac(message, SHARED_KEY)
    
    # Derive an AES key from the shared key (use SHA-256 and take the first 16 bytes for AES-128)
    aes_key = hashlib.sha256(SHARED_KEY).digest()[:16]
    
    # Generate a random 16-byte IV.
    iv = os.urandom(16)
    
    # Create AES cipher in CBC mode.
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    # Since master_secret is 32 bytes (a multiple of 16), we can encrypt directly.
    encrypted_master_body = cipher.encrypt(master_secret)
    encrypted_master = iv + encrypted_master_body  # Combine IV and ciphertext
    
    return encrypted_master, mac

def client_process_key_distribution(client_nonce, encrypted_master, mac):
    """
    Decrypts the encrypted master secret received from the server using AES in CBC mode.
    Verifies the MAC over (client_nonce || master_secret) using the shared key.
    
    Returns the master_secret if MAC verification succeeds.
    """
    # Derive the AES key as in the server.
    aes_key = hashlib.sha256(SHARED_KEY).digest()[:16]
    
    # Extract the IV (first 16 bytes) and ciphertext.
    iv = encrypted_master[:16]
    ciphertext = encrypted_master[16:]
    
    # Decrypt using AES in CBC mode.
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    master_secret = cipher.decrypt(ciphertext)
    
    message = client_nonce + master_secret
    if not verify_mac(message, mac, SHARED_KEY):
        raise ValueError("MAC verification failed in key distribution!")
    
    return master_secret
