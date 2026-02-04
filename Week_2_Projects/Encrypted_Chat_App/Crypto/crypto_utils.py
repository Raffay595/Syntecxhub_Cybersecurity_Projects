from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib

SECRET_KEY = hashlib.sha256(b"super_secret_password").digest()

def encrypt_message(message: str) -> bytes:
    iv = get_random_bytes(16)
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return iv + ciphertext

def decrypt_message(data: bytes) -> str:
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()