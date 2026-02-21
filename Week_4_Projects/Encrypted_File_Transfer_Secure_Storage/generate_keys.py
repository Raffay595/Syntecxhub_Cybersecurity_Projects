# generate_keys.py
import os

os.makedirs("keys", exist_ok=True)

# AES-256 key
with open("keys/aes.key", "wb") as f:
    f.write(os.urandom(32))

# HMAC-SHA256 key
with open("keys/hmac.key", "wb") as f:
    f.write(os.urandom(32))

print("Keys generated in keys/ folder")