import os
import json
import base64
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

VAULT_FILE = "vault.dat"
SALT_FILE = "salt.bin"
backend = default_backend()


def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    return kdf.derive(master_password.encode())


def encrypt_data(key, data):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()


def decrypt_data(key, encrypted_data):
    raw = base64.b64decode(encrypted_data.encode())
    iv = raw[:16]
    ciphertext = raw[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()


def load_vault(key):
    if not os.path.exists(VAULT_FILE):
        return {}

    with open(VAULT_FILE, "r") as f:
        encrypted_data = f.read()
    try:
        decrypted = decrypt_data(key, encrypted_data)
        return json.loads(decrypted)
    except:
        print("Wrong master password or corrupted vault.")
        exit()


def save_vault(key, vault):
    data = json.dumps(vault)
    encrypted = encrypt_data(key, data)
    with open(VAULT_FILE, "w") as f:
        f.write(encrypted)


def get_master_key():
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        print("Set a new master password.")
    else:
        with open(SALT_FILE, "rb") as f:
            salt = f.read()

    master_password = getpass.getpass("Enter master password: ")
    return derive_key(master_password, salt)


def add_entry(vault):
    site = input("Website: ")
    username = input("Username: ")
    password = getpass.getpass("Password: ")

    vault[site] = {"username": username, "password": password}
    print("Entry added.")


def retrieve_entry(vault):
    site = input("Website to retrieve: ")
    if site in vault:
        print(f"Username: {vault[site]['username']}")
        print(f"Password: {vault[site]['password']}")
    else:
        print("Entry not found.")


def delete_entry(vault):
    site = input("Website to delete: ")
    if site in vault:
        del vault[site]
        print("🗑 Entry deleted.")
    else:
        print("Entry not found.")


def search_entries(vault):
    term = input("Search term: ").lower()
    results = [site for site in vault if term in site.lower()]
    if results:
        print("Matches found:")
        for r in results:
            print("-", r)
    else:
        print("No matches.")


def main():
    key = get_master_key()
    vault = load_vault(key)

    while True:
        print("\nPassword Manager")
        print("1. Add Entry")
        print("2. Retrieve Entry")
        print("3. Delete Entry")
        print("4. Search")
        print("5. Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            add_entry(vault)
            save_vault(key, vault)
        elif choice == "2":
            retrieve_entry(vault)
        elif choice == "3":
            delete_entry(vault)
            save_vault(key, vault)
        elif choice == "4":
            search_entries(vault)
        elif choice == "5":
            save_vault(key, vault)
            print("Goodbye.")
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
