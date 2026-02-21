import os
import requests
import hmac
import hashlib
import urllib3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Suppress HTTPS warnings for self-signed certificate
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SERVER_URL = "https://127.0.0.1:5000"
CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB per chunk

# Load keys
with open("keys/aes.key", "rb") as f:
    AES_KEY = f.read()

with open("keys/hmac.key", "rb") as f:
    HMAC_KEY = f.read()

# Encrypt data chunk
def encrypt_chunk(data):
    aesgcm = AESGCM(AES_KEY)
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, data, None)
    return nonce + encrypted

# Generate HMAC
def generate_hmac(data):
    return hmac.new(HMAC_KEY, data, hashlib.sha256).digest()

# Upload a file in chunks
def upload_file(filepath):
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return

    file_id = os.path.basename(filepath)

    with open(filepath, "rb") as f:
        chunk_index = 0
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break

            encrypted_chunk = encrypt_chunk(chunk)
            mac = generate_hmac(encrypted_chunk)

            files = {
                "chunk": ("chunk", encrypted_chunk),
                "hmac": ("hmac", mac)
            }

            headers = {"File-ID": file_id}

            try:
                response = requests.post(
                    SERVER_URL + "/upload",
                    files=files,
                    headers=headers,
                    verify=False
                )
                print(f"Chunk {chunk_index} upload status:", response.status_code)
                print(f"Chunk {chunk_index} response:", response.text)
            except Exception as e:
                print("Upload request failed:", e)
                return

            chunk_index += 1

    print("File upload completed.")

# Download and decrypt
def download_file(file_id, output_path):
    response = requests.get(SERVER_URL + f"/download/{file_id}", verify=False)

    if response.status_code != 200:
        print("Download failed:", response.status_code, response.text)
        return

    encrypted_data = response.content
    aesgcm = AESGCM(AES_KEY)

    pos = 0
    with open(output_path, "wb") as out:
        while pos < len(encrypted_data):
            nonce = encrypted_data[pos:pos+12]
            pos += 12
            ciphertext = encrypted_data[pos:pos + CHUNK_SIZE + 16]  # AES-GCM tag = 16 bytes
            pos += len(ciphertext)
            decrypted = aesgcm.decrypt(nonce, ciphertext, None)
            out.write(decrypted)

    print("File downloaded and decrypted successfully")

# Main execution
if __name__ == "__main__":
    test_file = "testfile.txt"
    uploaded_file = "downloaded.txt"

    upload_file(test_file)
    download_file(test_file, uploaded_file)