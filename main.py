import argparse
import threading
import tkinter as tk
import sys
import logging

from server.bankServer import BankServer
from server.networkServer import run_network_server
from client.clientUI import ATMClientApp
from server.serverUI import ServerUI

# Configure global logging.
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
root_logger = logging.getLogger()
root_logger.propagate = True

def start_network_server(bank_server, host, port):
    run_network_server(bank_server, host=host, port=port)

def main():
    parser = argparse.ArgumentParser(description="Bank ATM Application")
    parser.add_argument("--client-only", action="store_true", help="Run client-only (no server UI)")
    parser.add_argument("--server-only", action="store_true", help="Run server-only (with server UI)")
    args = parser.parse_args()

    host = "0.0.0.0"
    port = 15000

    bank_server = BankServer()

    if args.server_only:
        server_thread = threading.Thread(target=start_network_server, args=(bank_server, host, port), daemon=True)
        server_thread.start()
        root = tk.Tk()
        server_ui = ServerUI(root, host, port)
        root.mainloop()
    elif args.client_only:
        root = tk.Tk()
        app = ATMClientApp(root)
        root.mainloop()
    else:
        server_thread = threading.Thread(target=start_network_server, args=(bank_server, host, port), daemon=True)
        server_thread.start()
        root = tk.Tk()
        root.title("Bank ATM")
        client_app = ATMClientApp(root)
        server_window = tk.Toplevel(root)
        server_ui = ServerUI(server_window, host, port)
        root.mainloop()

if __name__ == "__main__":
    main()