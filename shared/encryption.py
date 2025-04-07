import hashlib

SECRET_KEY = b"audit_secret_key" 

def xor_encrypt(message_bytes, key_bytes):
    return bytes([m ^ key_bytes[i % len(key_bytes)] for i, m in enumerate(message_bytes)])

def encrypt_message(message: str, encryption_key: bytes) -> bytes:
    message_bytes = message.encode('utf-8')
    return xor_encrypt(message_bytes, encryption_key)

def decrypt_message(cipher: bytes, encryption_key: bytes) -> str:
    decrypted_bytes = xor_encrypt(cipher, encryption_key)
    return decrypted_bytes.decode('utf-8')

def secure_audit_key():
    return hashlib.sha256(SECRET_KEY).digest()

def secure_encrypt_audit(text: str) -> str:
    key = secure_audit_key()
    message_bytes = text.encode('utf-8')
    cipher_bytes = xor_encrypt(message_bytes, key)
    return cipher_bytes.hex()

def secure_decrypt_audit(cipher_hex: str) -> str:
    key = secure_audit_key()
    cipher_bytes = bytes.fromhex(cipher_hex)
    return xor_encrypt(cipher_bytes, key).decode('utf-8')

def simple_encrypt(text, shift=3):
    encrypted = ""
    for char in text:
        encrypted += chr((ord(char) + shift) % 256)
    return encrypted

def simple_decrypt(text, shift=3):
    decrypted = ""
    for char in text:
        decrypted += chr((ord(char) - shift) % 256)
    return decrypted