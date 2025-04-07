import socket
import threading
import json
from server.bankServer import BankServer
import base64

class ClientHandler(threading.Thread):
    def __init__(self, conn, addr, bank_server):
        super().__init__()
        self.conn = conn
        self.addr = addr
        self.bank_server = bank_server

    def run(self):
        with self.conn:
            try:
                data = self.recv_all()
                if not data:
                    return
                request = json.loads(data.decode('utf-8'))
                response = self.handle_request(request)
                response_data = json.dumps(response).encode('utf-8')
                self.conn.sendall(response_data)
            except Exception as e:
                print("Error handling request:", e)

    def recv_all(self):
        chunks = []
        while True:
            chunk = self.conn.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)

    def handle_request(self, request):
        action = request.get("action")
        data = request.get("data", {})
        if action == "register":
            username = data.get("username")
            password = data.get("password")
            full_name = data.get("full_name")
            if not username or not password or not full_name:
                return {"status": "error", "message": "Missing fields"}
            success, msg = self.bank_server.register_user(username, password, full_name)
            return {"status": "success" if success else "error", "message": msg}
        elif action == "login":
            username = data.get("username")
            password = data.get("password")
            if not username or not password:
                return {"status": "error", "message": "Missing fields"}
            success, msg = self.bank_server.login(username, password)
            if success:
                full_name = self.bank_server.accounts[username].get("full_name", username)
                return {"status": "success", "message": msg, "full_name": full_name}
            else:
                return {"status": "error", "message": msg}
        elif action == "establish_secure_channel":
            username = data.get("username")
            client_nonce_b64 = data.get("client_nonce")
            if not username or not client_nonce_b64:
                return {"status": "error", "message": "Missing fields"}
            client_nonce = base64.b64decode(client_nonce_b64)
            encrypted_master, mac = self.bank_server.establish_secure_channel(username, client_nonce)
            return {"status": "success",
                    "encrypted_master": base64.b64encode(encrypted_master).decode('utf-8'),
                    "mac": base64.b64encode(mac).decode('utf-8')}
        elif action == "secure_transaction":
            username = data.get("username")
            operation = data.get("operation")
            payload_b64 = data.get("payload")
            payload_mac_b64 = data.get("payload_mac")
            if not username or not operation or not payload_b64 or not payload_mac_b64:
                return {"status": "error", "message": "Missing fields"}
            payload = base64.b64decode(payload_b64)
            payload_mac = base64.b64decode(payload_mac_b64)
            encrypted_result, result_mac, error = self.bank_server.secure_transaction(username, operation, payload, payload_mac)
            if error:
                return {"status": "error", "message": error}
            return {"status": "success",
                    "encrypted_result": base64.b64encode(encrypted_result).decode('utf-8'),
                    "result_mac": base64.b64encode(result_mac).decode('utf-8')}
        elif action == "transaction_history":
            username = data.get("username")
            if not username:
                return {"status": "error", "message": "Missing username"}
            history = self.bank_server.get_transaction_history(username)
            return {"status": "success", "history": history}
        else:
            return {"status": "error", "message": "Unknown action"}

def run_network_server(bank_server, host="0.0.0.0", port=15000):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Network server listening on {host}:{port}")
    while True:
        conn, addr = server_socket.accept()
        handler = ClientHandler(conn, addr, bank_server)
        handler.start()