import hashlib
import os
import hmac

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
    return os.urandom(32)  # 256-bit key

def generate_mac(message, key):
    return hmac.new(key, message, hashlib.sha256).digest()

def verify_mac(message, mac, key):
    expected_mac = hmac.new(key, message, hashlib.sha256).digest()
    print(f"Expected MAC: {expected_mac.hex()} - Actual MAC: {mac.hex()}")
    return hmac.compare_digest(mac, expected_mac)

def derive_keys(master_secret):
    encryption_key = hashlib.sha256(master_secret + b'encryption').digest()
    mac_key = hashlib.sha256(master_secret + b'mac').digest()
    print(f"Derived Encryption Key: {encryption_key.hex()}")
    return encryption_key, mac_key

def server_authenticated_key_distribution(client_nonce):
    master_secret = generate_master_secret()
    message = client_nonce + master_secret
    mac = generate_mac(message, SHARED_KEY)
    encrypted_master = bytes(a ^ b for a, b in zip(master_secret, SHARED_KEY * ((len(master_secret) // len(SHARED_KEY)) + 1)))
    return encrypted_master, mac

def client_process_key_distribution(client_nonce, encrypted_master, mac):
    master_secret = bytes(a ^ b for a, b in zip(encrypted_master, SHARED_KEY * ((len(encrypted_master) // len(SHARED_KEY)) + 1)))
    message = client_nonce + master_secret
    if not verify_mac(message, mac, SHARED_KEY):
        raise ValueError("MAC verification failed in key distribution!")
    return master_secret