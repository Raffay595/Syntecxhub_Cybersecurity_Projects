import socket
import threading
import sys
import os

sys.path.append(os.path.abspath("../crypto"))
from crypto_utils import decrypt_message

clients = []

def broadcast(message, sender_socket):
    for client in clients:
        if client != sender_socket:
            client.send(message)

def handle_client(client_socket, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    while True:
        try:
            data = client_socket.recv(4096)
            if not data:
                break

            with open("chat_log.bin", "ab") as f:
                f.write(data + b"\n")

            print(f"[ENCRYPTED MESSAGE RECEIVED FROM {addr}]")
            broadcast(data, client_socket)

        except:
            break

    clients.remove(client_socket)
    client_socket.close()
    print(f"[DISCONNECTED] {addr} left.")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 5000))
    server.listen()
    print("[SERVER STARTED] Listening on port 5000...")

    while True:
        client_socket, addr = server.accept()
        clients.append(client_socket)
        thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        thread.start()

start_server()
