import json, os
from datetime import datetime
from shared.encryption import secure_encrypt_audit, encrypt_message, decrypt_message
from shared.authentication import (hash_password, verify_password, SHARED_KEY,
                                     server_authenticated_key_distribution, derive_keys,
                                     generate_mac, verify_mac)

class BankServer:
    def __init__(self, accounts_file="data/accounts.json", audit_file="data/audit_log.json"):
        data_folder = os.path.dirname(accounts_file)
        if not os.path.exists(data_folder):
            os.makedirs(data_folder)
        self.accounts_file = accounts_file
        self.audit_file = audit_file
        self.load_accounts()
        self.load_audit_log()
        self.sessions = {}  # To store session keys for each logged-in user

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

    def register_user(self, username, password, full_name):
        if username in self.accounts:
            return False, "Username already exists."
        hashed = hash_password(password)
        # Save the password under the key "password_hash" and store the full name.
        self.accounts[username] = {"password_hash": hashed, "balance": 0.0, "full_name": full_name}
        self.save_accounts()
        self.log_audit(username, "Registered new account")
        return True, "Registration successful."

    def login(self, username, password):
        if username in self.accounts and verify_password(password, self.accounts[username]["password_hash"]):
            self.log_audit(username, "Logged in")
            return True, "Login successful."
        else:
            return False, "Invalid username or password."

    def establish_secure_channel(self, username, client_nonce):
        encrypted_master, mac = server_authenticated_key_distribution(client_nonce)
        master_secret = bytes(a ^ b for a, b in zip(encrypted_master, SHARED_KEY * ((len(encrypted_master) // len(SHARED_KEY)) + 1)))
        encryption_key, mac_key = derive_keys(master_secret)
        self.sessions[username] = {"encryption_key": encryption_key, "mac_key": mac_key}
        return encrypted_master, mac

    def secure_transaction(self, username, operation, payload: bytes, payload_mac: bytes):
        if username not in self.sessions:
            return None, None, "Secure channel not established."
        session = self.sessions[username]
        encryption_key = session["encryption_key"]
        mac_key = session["mac_key"]
        if not verify_mac(payload, payload_mac, mac_key):
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
        return encrypted_result, result_mac, None