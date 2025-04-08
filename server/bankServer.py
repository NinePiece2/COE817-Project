import json
import os
from datetime import datetime
from shared.encryption import secure_encrypt_audit, encrypt_message, decrypt_message
from shared.authentication import (hash_password, verify_password, SHARED_KEY,
                                     server_authenticated_key_distribution, derive_keys,
                                     generate_mac, verify_mac, generate_master_secret)
import logging
import hashlib
from Crypto.Cipher import AES

logger = logging.getLogger(__name__)
logger.propagate = True

class BankServer:
    def __init__(self, accounts_file="data/accounts.json", audit_file="data/audit_log.json"):
        data_folder = os.path.dirname(accounts_file)
        if not os.path.exists(data_folder):
            os.makedirs(data_folder)
        self.accounts_file = accounts_file
        self.audit_file = audit_file
        self.load_accounts()
        self.load_audit_log()
        self.sessions = {}

    def load_accounts(self):
        if os.path.exists(self.accounts_file):
            with open(self.accounts_file, "r") as f:
                self.accounts = json.load(f)
        else:
            self.accounts = {}

    def save_accounts(self):
        with open(self.accounts_file, "w") as f:
            json.dump(self.accounts, f, indent=4)

    def load_audit_log(self):
        if os.path.exists(self.audit_file):
            with open(self.audit_file, "r") as f:
                self.audit_log = json.load(f)
        else:
            self.audit_log = []

    def save_audit_log(self):
        with open(self.audit_file, "w") as f:
            json.dump(self.audit_log, f, indent=4)

    def log_audit(self, username, action):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"{username} | {action} | {timestamp}"
        encrypted_entry = secure_encrypt_audit(entry)
        self.audit_log.append(encrypted_entry)
        self.save_audit_log()
        logger.debug("Audit log updated for user '%s' action '%s'", username, action)

    def register_user(self, username, password, full_name):
        if username in self.accounts:
            logger.debug("Registration failed: Username '%s' already exists", username)
            return False, "Username already exists."
        hashed = hash_password(password)
        self.accounts[username] = {"password_hash": hashed, "balance": 0.0, "full_name": full_name}
        self.save_accounts()
        self.log_audit(username, "Registered new account")
        logger.debug("User '%s' registered successfully", username)
        return True, "Registration successful."

    def login(self, username, password):
        if username in self.accounts and verify_password(password, self.accounts[username]["password_hash"]):
            self.log_audit(username, "Logged in")
            logger.debug("User '%s' logged in successfully", username)
            return True, "Login successful."
        else:
            logger.debug("Login failed for user '%s'", username)
            return False, "Invalid username or password."

    def establish_secure_channel(self, username, client_nonce):
        """
        Establishes the secure channel by generating a master_secret,
        encrypting it with AES in CBC mode, and computing a MAC over
        (client_nonce || master_secret). The server stores the master_secret
        internally (via derived session keys) and returns the encrypted_master and MAC.
        """
        # Generate the master secret (server side)
        master_secret = generate_master_secret()  # 32-byte value
        
        # Prepare message for MAC computation
        message = client_nonce + master_secret
        mac = generate_mac(message, SHARED_KEY)
        
        # Derive the AES key from SHARED_KEY (using SHA-256; take 16 bytes for AES-128)
        aes_key = hashlib.sha256(SHARED_KEY).digest()[:16]
        # Generate a random IV of 16 bytes.
        iv = os.urandom(16)
        # Create an AES cipher in CBC mode.
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        # Encrypt the master secret (master_secret is 32 bytes, a multiple of the block size)
        encrypted_master_body = cipher.encrypt(master_secret)
        # Concatenate the IV with the ciphertext.
        encrypted_master = iv + encrypted_master_body
        
        # Now derive session keys from the master secret.
        encryption_key, mac_key = derive_keys(master_secret)
        self.sessions[username] = {"encryption_key": encryption_key, "mac_key": mac_key}
        
        logger.debug("Secure channel established for user '%s'", username)
        return encrypted_master, mac

    def secure_transaction(self, username, operation, payload: bytes, payload_mac: bytes):
        if username not in self.sessions:
            logger.debug("Secure channel not established for user '%s'", username)
            return None, None, "Secure channel not established."
        session = self.sessions[username]
        encryption_key = session["encryption_key"]
        mac_key = session["mac_key"]
        if not verify_mac(payload, payload_mac, mac_key):
            logger.debug("MAC verification failed for user '%s' operation '%s'", username, operation)
            return None, None, "MAC verification failed for transaction."
        decrypted = decrypt_message(payload, encryption_key)
        if operation == "deposit":
            try:
                amount = float(decrypted)
                if amount <= 0:
                    return None, None, "Deposit amount must be positive."
            except ValueError:
                return None, None, "Invalid deposit amount."
            self.accounts[username]["balance"] += amount
            self.save_accounts()
            self.log_audit(username, f"Deposited ${amount:.2f}")
            result = f"Deposited ${amount:.2f}. New balance: ${self.accounts[username]['balance']:.2f}"
        elif operation == "withdraw":
            try:
                amount = float(decrypted)
                if amount <= 0:
                    return None, None, "Withdrawal amount must be positive."
            except ValueError:
                return None, None, "Invalid withdrawal amount."
            if self.accounts[username]["balance"] < amount:
                return None, None, "Insufficient funds."
            self.accounts[username]["balance"] -= amount
            self.save_accounts()
            self.log_audit(username, f"Withdrew ${amount:.2f}")
            result = f"Withdrew ${amount:.2f}. New balance: ${self.accounts[username]['balance']:.2f}"
        elif operation == "balance":
            balance = self.accounts[username]["balance"]
            self.log_audit(username, "Checked balance")
            result = f"Your current balance is: ${balance:.2f}"
        else:
            return None, None, "Unknown operation."

        encrypted_result = encrypt_message(result, encryption_key)
        result_mac = generate_mac(encrypted_result, mac_key)
        logger.debug("Transaction '%s' processed for user '%s'", operation, username)
        return encrypted_result, result_mac, None

    def get_transaction_history(self, username):
        from shared.encryption import secure_decrypt_audit
        entries = []
        final_balance = 0.0
        for entry in self.audit_log:
            try:
                decrypted = secure_decrypt_audit(entry)
                parts = decrypted.split(" | ")
                if len(parts) != 3:
                    continue
                user, action, timestamp = parts
                if user == username:
                    if action.startswith("Deposited $") or action.startswith("Withdrew $"):
                        entries.append((timestamp, action))
                        if action.startswith("Deposited $"):
                            try:
                                amount_str = action[len("Deposited $"):].split()[0]
                                amount = float(amount_str)
                                final_balance += amount
                            except:
                                pass
                        elif action.startswith("Withdrew $"):
                            try:
                                amount_str = action[len("Withdrew $"):].split()[0]
                                amount = float(amount_str)
                                final_balance -= amount
                            except:
                                pass
            except Exception as e:
                continue
        logger.debug("Transaction history retrieved for user '%s'", username)
        return {"entries": entries, "final_balance": final_balance}
