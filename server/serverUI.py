import tkinter as tk
from tkinter import scrolledtext
import logging
import queue
from logging.handlers import QueueHandler, QueueListener

class TextHandler(logging.Handler):
    """This logging handler sends log records to a Tkinter Text widget."""
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record)
        # Insert the message in the text widget and scroll it.
        def append():
            self.text_widget.insert(tk.END, msg + "\n")
            self.text_widget.see(tk.END)
        self.text_widget.after(0, append)

class ServerUI:
    def __init__(self, master, host, port):
        self.master = master
        self.master.title("Bank ATM Server")
        self.master.geometry("600x400")
        self.master.configure(bg="#121212")

        # Set the icon if available.
        ico_path = "images/favicon.ico"
        try:
            self.master.iconbitmap(ico_path)
        except Exception as e:
            logging.error("Error setting icon: %s", e)

        info_text = f"Server running on {host}:{port}"
        self.info_label = tk.Label(master, text=info_text, font=("Arial", 14),
                                   bg="#121212", fg="#FFFFFF")
        self.info_label.pack(pady=10)

        self.debug_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=70,
                                                     height=15, font=("Courier", 10),
                                                     bg="#121212", fg="#FFFFFF", insertbackground='white')
        self.debug_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.restore_btn = tk.Button(master, text="Restore Stdout",
                                     command=self.restore_stdout,
                                     bg="#4CAF50", fg="#FFFFFF")
        self.restore_btn.pack(pady=5)

        # Set up the logging queue.
        self.log_queue = queue.Queue()

        # Create a QueueHandler that directs log records into the queue.
        self.queue_handler = QueueHandler(self.log_queue)
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        self.queue_handler.setFormatter(formatter)

        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        root_logger.addHandler(self.queue_handler)

        self.text_handler = TextHandler(self.debug_area)
        self.text_handler.setFormatter(formatter)

        self.queue_listener = QueueListener(self.log_queue, self.text_handler)
        self.queue_listener.start()

        logging.getLogger().info("Server UI started. Debug output will appear here.")

    def restore_stdout(self):
        import sys
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        logging.getLogger().info("Standard output restored.")
