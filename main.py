import argparse
import threading
import tkinter as tk
import sys

from server.bankServer import BankServer
from server.networkServer import run_network_server
from client.clientUI import ATMClientApp

# We'll add a new module for the server UI (see below)
from server.serverUI import ServerUI

def start_network_server(bank_server, host, port, debug_callback=None):
    # Optionally, you can pass a debug_callback that the network server or BankServer uses to log messages.
    run_network_server(bank_server, host=host, port=port)

def main():
    parser = argparse.ArgumentParser(description="SecureBank Application")
    parser.add_argument("--client-only", action="store_true", help="Run client-only (no server GUI)")
    parser.add_argument("--server-only", action="store_true", help="Run server-only (with server UI)")
    args = parser.parse_args()

    # Define the host and port
    host = "0.0.0.0"
    port = 15000

    bank_server = BankServer()

    if args.server_only:
        # Start the network server and create a Server UI
        # Launch the network server in a background thread.
        server_thread = threading.Thread(target=start_network_server, args=(bank_server, host, port), daemon=True)
        server_thread.start()

        # Create the Server GUI which shows address, port and debug output.
        root = tk.Tk()
        server_ui = ServerUI(root, host, port)
        root.mainloop()

    elif args.client_only:
        # Run the client GUI only. We assume the server is already running externally.
        root = tk.Tk()
        app = ATMClientApp(root)
        root.mainloop()

    else:
        # Run both the server and client GUI(s) in one application.
        # Note: Running multiple Tk windows can be tricky; here we use the main window as client and
        # launch a Toplevel for the server UI.
        # Start network server in a background thread.
        server_thread = threading.Thread(target=start_network_server, args=(bank_server, host, port), daemon=True)
        server_thread.start()

        root = tk.Tk()
        root.title("Bank ATM")
        # Create the client UI in the main window
        client_app = ATMClientApp(root)

        # Create a server UI as a separate Toplevel
        server_window = tk.Toplevel(root)
        server_ui = ServerUI(server_window, host, port)

        root.mainloop()

if __name__ == "__main__":
    main()