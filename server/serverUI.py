import tkinter as tk
from tkinter import scrolledtext
import sys
import os

class TextRedirector(object):
    def __init__(self, text_widget):
        self.text_widget = text_widget
    def write(self, str):
        self.text_widget.insert(tk.END, str)
        self.text_widget.see(tk.END)
    def flush(self):
        pass

class ServerUI:
    def __init__(self, master, host, port):
        self.master = master
        self.master.title("Bank ATM Server")
        self.master.geometry("600x400")
        self.master.configure(bg="#121212")

        ico_path = "images/favicon.ico"
        if os.path.exists(ico_path):
            self.master.iconbitmap(ico_path)
        else:
            if getattr(sys, 'frozen', False):
                base_path = sys._MEIPASS
            else:
                base_path = os.path.abspath(".")

            icon_path = os.path.join(base_path, "favicon.ico")

            try:
                self.master.iconbitmap(icon_path)
            except Exception as e:
                print(f"Error setting icon: {e}")

        # Display server address and port
        info_text = f"Server running on {host}:{port}"
        self.info_label = tk.Label(master, text=info_text, font=("Arial", 14), bg="#121212", fg="#FFFFFF")
        self.info_label.pack(pady=10)

        # Create a scrolled text area to display debug information
        self.debug_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=70, height=15, font=("Courier", 10), bg="#121212", fg="#FFFFFF", insertbackground='white')
        self.debug_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Redirect stdout to our text widget so prints appear in the GUI.
        sys.stdout = TextRedirector(self.debug_area)
        sys.stderr = TextRedirector(self.debug_area)

        # Optionally, you can add a button to restore sys.stdout if needed.
        self.restore_btn = tk.Button(master, text="Restore Stdout", command=self.restore_stdout, bg="#4CAF50", fg="#FFFFFF")
        self.restore_btn.pack(pady=5)

    def restore_stdout(self):
        import sys
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        print("Standard output restored.")