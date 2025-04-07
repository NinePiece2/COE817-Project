import threading
import tkinter as tk
import sys
from server.bankServer import BankServer
from server.networkServer import run_network_server
from client.clientUI import ATMClientApp

def start_network_server():
    bank_server = BankServer()
    run_network_server(bank_server, host="0.0.0.0", port=15000)

def main():
    num_clients = 1
    if len(sys.argv) > 1:
        try:
            num_clients = int(sys.argv[1])
        except ValueError:
            print("Invalid number of clients specified. Defaulting to 1.")
            num_clients = 1

    # Start the network server in a background daemon thread.
    server_thread = threading.Thread(target=start_network_server, daemon=True)
    server_thread.start()

    # Create the main Tkinter window and additional client windows as needed.
    root = tk.Tk()
    app_instances = []
    app = ATMClientApp(root)
    app_instances.append(app)
    for i in range(1, num_clients):
        new_window = tk.Toplevel(root)
        app_instance = ATMClientApp(new_window)
        app_instances.append(app_instance)

    root.mainloop()

if __name__ == "__main__":
    main()