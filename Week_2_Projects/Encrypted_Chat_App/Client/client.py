import socket
import threading
import sys
import os

sys.path.append(os.path.abspath("../crypto"))
from crypto_utils import encrypt_message, decrypt_message

def receive_messages(sock):
    while True:
        try:
            data = sock.recv(4096)
            if data:
                print("\nFriend:", decrypt_message(data))
        except:
            break

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 5000))

    threading.Thread(target=receive_messages, args=(client,), daemon=True).start()

    print("Connected to secure chat. Type messages.")

    while True:
        msg = input("You: ")
        encrypted = encrypt_message(msg)
        client.send(encrypted)

start_client()
