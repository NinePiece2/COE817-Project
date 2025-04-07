import os
import json
from shared.encryption import secure_decrypt_audit

def main():
    # Path to the audit log JSON file.
    audit_log_path = os.path.join("data", "audit_log.json")
    output_file = "audit_log_decrypted.txt"
    
    if not os.path.exists(audit_log_path):
        print(f"Audit log file '{audit_log_path}' does not exist.")
        return
    
    # Read the encrypted audit log entries.
    with open(audit_log_path, "r") as f:
        try:
            audit_data = json.load(f)
        except json.JSONDecodeError as e:
            print("Error decoding JSON from the audit log:", e)
            return
    
    decrypted_entries = []
    for entry in audit_data:
        try:
            # Decrypt each audit log entry.
            decrypted = secure_decrypt_audit(entry)
            decrypted_entries.append(decrypted)
        except Exception as e:
            print(f"Error decrypting entry: {entry}\nError: {e}")
            decrypted_entries.append(f"Error decrypting entry: {entry}")
    
    # Write the decrypted entries to the output text file.
    with open(output_file, "w") as f:
        for entry in decrypted_entries:
            f.write(entry + "\n")
    
    print(f"Decrypted audit log written to '{output_file}'")

if __name__ == "__main__":
    main()