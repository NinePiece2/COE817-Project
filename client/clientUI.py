import tkinter as tk
from tkinter import messagebox, ttk
import socket, json, base64, os
from shared.authentication import client_process_key_distribution, derive_keys, generate_mac
from shared.encryption import encrypt_message, decrypt_message

# Global color constants
BG_COLOR = "#121212"               # Light blue background
BUTTON_PRIMARY_BG = "#4CAF50"      # Primary button background
BUTTON_SECONDARY_BG = "#4CAF50"    # Secondary button background
BUTTON_TERTIARY_BG = "#1e88e5"     # Tertiary button background (e.g., Balance Inquiry)
BUTTON_ERROR_BG = "#e53935"        # Error action button background (e.g., Withdraw)
BUTTON_LOGOUT_BG = "#757575"       # Logout button background
BUTTON_FG = "white"                # Button foreground (text) color
LABEL_FONT = ("Arial", 18)
DEFAULT_FONT = ("Arial", 18)
LABEL_FONT_COLOR = "white"         # Label text color

# Helper function to send a JSON request to the server and receive a response.
def send_request(request):
    HOST = '127.0.0.1'
    PORT = 15000
    try:
        with socket.create_connection((HOST, PORT), timeout=5) as sock:
            sock.sendall(json.dumps(request).encode('utf-8'))
            sock.shutdown(socket.SHUT_WR)
            response_data = sock.recv(4096)
            return json.loads(response_data.decode('utf-8'))
    except Exception as e:
        return {"status": "error", "message": str(e)}

class ATMClientApp:
    def __init__(self, master):
        self.master = master
        # Set the window size to be bigger
        self.master.geometry("800x600")
        self.current_user = None
        self.session_keys = None  # Holds encryption and MAC keys
        self.master.title("Bank ATM")
        
        ico_path = "images/favicon.ico"
        if os.path.exists(ico_path):
            try:
                self.master.iconbitmap(ico_path)
            except Exception as e:
                print("iconbitmap failed:", e)
        else:
            print("favicon.ico not found.")

        png_path = "images/favicon.png"
        if os.path.exists(png_path):
            try:
                icon = tk.PhotoImage(file=png_path)
                self.master.iconphoto(True, icon)
                self.master.icon_image = icon 
            except Exception as e:
                print("iconphoto failed:", e)
        else:
            print("favicon.png not found.")
        
        self.master.configure(bg=BG_COLOR)
        self.main_frame = tk.Frame(master, bg=BG_COLOR)
        self.main_frame.pack(padx=20, pady=20)

        self.create_login_frame()
        self.create_register_frame()
        self.create_menu_frame()

        self.show_frame(self.login_frame)

    def create_login_frame(self):
        self.login_frame = tk.Frame(self.main_frame, bg=BG_COLOR)
        tk.Label(self.login_frame, text="Login", font=LABEL_FONT, bg=BG_COLOR, fg=LABEL_FONT_COLOR)\
            .grid(row=0, column=0, columnspan=2, pady=10)
        tk.Label(self.login_frame, text="Username:",font=LABEL_FONT, bg=BG_COLOR, fg=LABEL_FONT_COLOR)\
            .grid(row=1, column=0, sticky="e")
        self.login_username_entry = tk.Entry(self.login_frame, font=DEFAULT_FONT)
        self.login_username_entry.grid(row=1, column=1)
        tk.Label(self.login_frame, text="Password:", font=LABEL_FONT, bg=BG_COLOR, fg=LABEL_FONT_COLOR)\
            .grid(row=2, column=0, sticky="e")
        self.login_password_entry = tk.Entry(self.login_frame, show="*", font=DEFAULT_FONT)
        self.login_password_entry.grid(row=2, column=1)
        login_btn = tk.Button(self.login_frame, text="Login", command=self.login,
                              bg=BUTTON_PRIMARY_BG, fg=BUTTON_FG, font=DEFAULT_FONT)
        login_btn.grid(row=3, column=0, columnspan=2, pady=10)
        tk.Button(self.login_frame, text="Register",
                  command=lambda: self.show_frame(self.register_frame),
                  bg=BUTTON_SECONDARY_BG, fg=BUTTON_FG, font=DEFAULT_FONT)\
            .grid(row=4, column=0, columnspan=2)
        
        # Bind Enter key on entries to trigger login.
        self.login_username_entry.bind("<Return>", lambda event: self.login())
        self.login_password_entry.bind("<Return>", lambda event: self.login())

    def create_register_frame(self):
        self.register_frame = tk.Frame(self.main_frame, bg=BG_COLOR)
        tk.Label(self.register_frame, text="Register", font=LABEL_FONT, bg=BG_COLOR, fg=LABEL_FONT_COLOR)\
            .grid(row=0, column=0, columnspan=2, pady=10)
        tk.Label(self.register_frame, text="Full Name:", font=LABEL_FONT, bg=BG_COLOR, fg=LABEL_FONT_COLOR)\
            .grid(row=1, column=0, sticky="e")
        self.reg_fullname_entry = tk.Entry(self.register_frame, font=DEFAULT_FONT)
        self.reg_fullname_entry.grid(row=1, column=1)
        tk.Label(self.register_frame, text="Username:", font=LABEL_FONT, bg=BG_COLOR, fg=LABEL_FONT_COLOR)\
            .grid(row=2, column=0, sticky="e")
        self.reg_username_entry = tk.Entry(self.register_frame, font=DEFAULT_FONT)
        self.reg_username_entry.grid(row=2, column=1)
        tk.Label(self.register_frame, text="Password:", font=LABEL_FONT, bg=BG_COLOR, fg=LABEL_FONT_COLOR)\
            .grid(row=3, column=0, sticky="e")
        self.reg_password_entry = tk.Entry(self.register_frame, show="*", font=DEFAULT_FONT)
        self.reg_password_entry.grid(row=3, column=1)
        register_btn = tk.Button(self.register_frame, text="Register", command=self.register,
                                 bg=BUTTON_PRIMARY_BG, fg=BUTTON_FG, font=DEFAULT_FONT)
        register_btn.grid(row=4, column=0, columnspan=2, pady=10)
        tk.Button(self.register_frame, text="Back to Login",
                  command=lambda: self.show_frame(self.login_frame),
                  bg=BUTTON_SECONDARY_BG, fg=BUTTON_FG, font=DEFAULT_FONT)\
            .grid(row=5, column=0, columnspan=2)
        
        # Bind Enter key on entries to trigger register.
        self.reg_fullname_entry.bind("<Return>", lambda event: self.register())
        self.reg_username_entry.bind("<Return>", lambda event: self.register())
        self.reg_password_entry.bind("<Return>", lambda event: self.register())

    def create_menu_frame(self):
        self.menu_frame = tk.Frame(self.main_frame, bg=BG_COLOR)

        # dynamic welcome label
        self.welcome_label = tk.Label(self.menu_frame, text="Welcome", font=LABEL_FONT, bg=BG_COLOR, fg=LABEL_FONT_COLOR)
        self.welcome_label.grid(row=0, column=0, columnspan=2, pady=10)
        tk.Button(self.menu_frame, text="Deposit", width=15, command=self.deposit_window,
                  bg="#43a047", fg=BUTTON_FG, font=DEFAULT_FONT)\
            .grid(row=1, column=0, pady=5)
        tk.Button(self.menu_frame, text="Withdraw", width=15, command=self.withdraw_window,
                  bg=BUTTON_ERROR_BG, fg=BUTTON_FG, font=DEFAULT_FONT)\
            .grid(row=1, column=1, pady=5)
        tk.Button(self.menu_frame, text="Balance Inquiry", width=15, command=self.balance_inquiry,
                  bg=BUTTON_TERTIARY_BG, fg=BUTTON_FG, font=DEFAULT_FONT)\
            .grid(row=2, column=0, pady=5)
        tk.Button(self.menu_frame, text="Transaction History", width=15, command=self.transaction_history,
                  bg=BUTTON_SECONDARY_BG, fg=BUTTON_FG, font=DEFAULT_FONT)\
            .grid(row=2, column=1, pady=5)
        tk.Button(self.menu_frame, text="Logout", width=15, command=self.logout,
                  bg=BUTTON_LOGOUT_BG, fg=BUTTON_FG, font=DEFAULT_FONT)\
            .grid(row=3, column=0, pady=5)

    def clear_entries(self, frame):
        for widget in frame.winfo_children():
            if isinstance(widget, tk.Entry):
                widget.delete(0, tk.END)

    def show_frame(self, frame):
        # Clear text fields in both login and register frames
        self.clear_entries(self.login_frame)
        self.clear_entries(self.register_frame)

        # Hide all frames and show the selected one
        for child in self.main_frame.winfo_children():
            child.pack_forget()
        frame.pack()

    def login(self):
        username = self.login_username_entry.get()
        password = self.login_password_entry.get()
        request = {"action": "login", "data": {"username": username, "password": password}}
        response = send_request(request)
        if response.get("status") == "success":
            self.current_user = username
            full_name = response.get("full_name", username)
            messagebox.showinfo("Success", f"{response.get('message')}\nWelcome, {full_name}!")
            # Update the welcome label with the full name
            self.welcome_label.config(text=f"Welcome, {full_name}!")

            # Establish secure channel.
            client_nonce = os.urandom(16)
            request_sc = {"action": "establish_secure_channel", "data": {"username": username,
                        "client_nonce": base64.b64encode(client_nonce).decode('utf-8')}}
            response_sc = send_request(request_sc)
            if response_sc.get("status") == "success":
                try:
                    encrypted_master = base64.b64decode(response_sc.get("encrypted_master"))
                    mac = base64.b64decode(response_sc.get("mac"))
                    master_secret = client_process_key_distribution(client_nonce, encrypted_master, mac)
                    encryption_key, mac_key = derive_keys(master_secret)
                    self.session_keys = {"encryption_key": encryption_key, "mac_key": mac_key}
                except Exception as e:
                    messagebox.showerror("Error", "Key distribution failed: " + str(e))
                    return
                self.show_frame(self.menu_frame)
            else:
                messagebox.showerror("Error", "Failed to establish secure channel.")
        else:
            messagebox.showerror("Error", response.get("message"))

    def register(self):
        full_name = self.reg_fullname_entry.get()
        username = self.reg_username_entry.get()
        password = self.reg_password_entry.get()
        request = {"action": "register", "data": {"username": username, "password": password, "full_name": full_name}}
        response = send_request(request)
        if response.get("status") == "success":
            messagebox.showinfo("Success", response.get("message"))
            self.show_frame(self.login_frame)
        else:
            messagebox.showerror("Error", response.get("message"))

    def deposit_window(self):
        self.popup_window("Deposit", "Enter deposit amount:", self.perform_deposit)

    def withdraw_window(self):
        self.popup_window("Withdraw", "Enter withdrawal amount:", self.perform_withdraw)

    def popup_window(self, title, prompt, action):
        popup = tk.Toplevel(self.master)
        popup.title(title)
        popup.configure(bg=BG_COLOR)
        tk.Label(popup, text=prompt, bg=BG_COLOR, font=DEFAULT_FONT, fg=LABEL_FONT_COLOR).pack(padx=10, pady=10)
        amount_entry = tk.Entry(popup, font=DEFAULT_FONT)
        amount_entry.pack(padx=10, pady=10)
        btn = tk.Button(popup, text=title, command=lambda: self.handle_amount(popup, amount_entry, action),
                        bg=BUTTON_PRIMARY_BG, fg=BUTTON_FG, font=DEFAULT_FONT)
        btn.pack(padx=10, pady=10)
        amount_entry.bind("<Return>", lambda event: self.handle_amount(popup, amount_entry, action))

    def handle_amount(self, popup, amount_entry, action):
        amount = amount_entry.get()
        popup.destroy()
        action(amount)

    def perform_deposit(self, amount):
        if not self.session_keys:
            messagebox.showerror("Error", "Secure channel not established.")
            return
        encryption_key = self.session_keys["encryption_key"]
        mac_key = self.session_keys["mac_key"]
        payload = encrypt_message(amount, encryption_key)
        payload_mac = generate_mac(payload, mac_key)
        request = {"action": "secure_transaction", "data": {"username": self.current_user,
                    "operation": "deposit",
                    "payload": base64.b64encode(payload).decode('utf-8'),
                    "payload_mac": base64.b64encode(payload_mac).decode('utf-8')}}
        response = send_request(request)
        if response.get("status") == "error":
            messagebox.showerror("Deposit Error", response.get("message"))
        else:
            encrypted_result = base64.b64decode(response.get("encrypted_result"))
            result = decrypt_message(encrypted_result, encryption_key)
            messagebox.showinfo("Deposit", result)

    def perform_withdraw(self, amount):
        if not self.session_keys:
            messagebox.showerror("Error", "Secure channel not established.")
            return
        encryption_key = self.session_keys["encryption_key"]
        mac_key = self.session_keys["mac_key"]
        payload = encrypt_message(amount, encryption_key)
        payload_mac = generate_mac(payload, mac_key)
        request = {"action": "secure_transaction", "data": {"username": self.current_user,
                    "operation": "withdraw",
                    "payload": base64.b64encode(payload).decode('utf-8'),
                    "payload_mac": base64.b64encode(payload_mac).decode('utf-8')}}
        response = send_request(request)
        if response.get("status") == "error":
            messagebox.showerror("Withdrawal Error", response.get("message"))
        else:
            encrypted_result = base64.b64decode(response.get("encrypted_result"))
            result = decrypt_message(encrypted_result, encryption_key)
            messagebox.showinfo("Withdraw", result)

    def balance_inquiry(self):
        if not self.session_keys:
            messagebox.showerror("Error", "Secure channel not established.")
            return
        encryption_key = self.session_keys["encryption_key"]
        mac_key = self.session_keys["mac_key"]
        # Use a non-empty payload for balance inquiry (e.g., "balance")
        payload = encrypt_message("balance", encryption_key)
        payload_mac = generate_mac(payload, mac_key)
        request = {"action": "secure_transaction", "data": {"username": self.current_user,
                    "operation": "balance",
                    "payload": base64.b64encode(payload).decode('utf-8'),
                    "payload_mac": base64.b64encode(payload_mac).decode('utf-8')}}
        response = send_request(request)
        if response.get("status") == "error":
            messagebox.showerror("Balance Inquiry Error", response.get("message"))
        else:
            encrypted_result = base64.b64decode(response.get("encrypted_result"))
            result = decrypt_message(encrypted_result, encryption_key)
            messagebox.showinfo("Balance Inquiry", result)
    
    def transaction_history(self):
        """Requests the transaction history over the network and displays it in the main window with a running balance column."""
        request = {"action": "transaction_history", "data": {"username": self.current_user}}
        response = send_request(request)
        if response.get("status") != "success":
            messagebox.showerror("Error", response.get("message"))
            return

        history = response.get("history", {})
        entries = history.get("entries", [])
        
        # Sort entries by timestamp
        entries.sort(key=lambda x: x[0])
        
        # Compute running balance.
        running_balance = 0.0
        new_entries = []
        for timestamp, action in entries:
            if action.startswith("Deposited $"):
                try:
                    amount_str = action[len("Deposited $"):].split()[0]
                    amount = float(amount_str)
                    running_balance += amount
                except Exception as e:
                    print("Error parsing deposit amount:", e)
            elif action.startswith("Withdrew $"):
                try:
                    amount_str = action[len("Withdrew $"):].split()[0]
                    amount = float(amount_str)
                    running_balance -= amount
                except Exception as e:
                    print("Error parsing withdrawal amount:", e)
            new_entries.append((timestamp, action, f"${running_balance:.2f}"))
        
        # Create or update a dedicated history frame within the main window.
        self.history_frame = tk.Frame(self.main_frame, bg=BG_COLOR)
        
        header = tk.Label(self.history_frame, text="Transaction History", font=LABEL_FONT, bg=BG_COLOR, fg=LABEL_FONT_COLOR)
        header.pack(pady=10)
        
        # Create a Treeview widget with three columns: Timestamp, Action, and Balance.
        tree = ttk.Treeview(self.history_frame, columns=("timestamp", "action", "balance"), show="headings")
        tree.heading("timestamp", text="Timestamp")
        tree.heading("action", text="Action")
        tree.heading("balance", text="Balance")
        tree.column("timestamp", width=200, anchor="center")
        tree.column("action", width=280, anchor="center")
        tree.column("balance", width=100, anchor="center")
        
        for timestamp, action, balance in new_entries:
            tree.insert("", "end", values=(timestamp, action, balance))
        tree.pack(expand=True, fill="both", padx=10, pady=10)
        
        # Add a back button to return to the main menu.
        back_btn = tk.Button(self.history_frame, text="Back", command=lambda: self.show_frame(self.menu_frame),
                            bg=BUTTON_PRIMARY_BG, fg=BUTTON_FG, font=DEFAULT_FONT)
        back_btn.pack(pady=10)
        
        self.show_frame(self.history_frame)

    def logout(self):
        self.current_user = None
        self.session_keys = None
        self.login_username_entry.delete(0, tk.END)
        self.login_password_entry.delete(0, tk.END)
        self.show_frame(self.login_frame)

if __name__ == "__main__":
    root = tk.Tk()
    app = ATMClientApp(root)
    root.mainloop()