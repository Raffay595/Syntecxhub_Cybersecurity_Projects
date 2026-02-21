import os
import hmac
import hashlib
from flask import Flask, request, jsonify, send_file
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)
STORAGE_DIR = "storage"
os.makedirs(STORAGE_DIR, exist_ok=True)

# Load AES and HMAC keys
with open("keys/aes.key", "rb") as f:
    AES_KEY = f.read()

with open("keys/hmac.key", "rb") as f:
    HMAC_KEY = f.read()

# Verify HMAC
def verify_hmac(data, received_hmac):
    computed = hmac.new(HMAC_KEY, data, hashlib.sha256).digest()
    return hmac.compare_digest(computed, received_hmac)

# Upload route
@app.route("/upload", methods=["POST"])
def upload():
    file_id = request.headers.get("File-ID")
    if not file_id:
        return jsonify({"error": "Missing File-ID header"}), 400

    if "chunk" not in request.files or "hmac" not in request.files:
        return jsonify({"error": "Missing chunk or hmac"}), 400

    chunk = request.files["chunk"].read()
    received_hmac = request.files["hmac"].read()

    if not verify_hmac(chunk, received_hmac):
        return jsonify({"error": "Integrity check failed"}), 400

    path = f"{STORAGE_DIR}/{file_id}.enc"
    with open(path, "ab") as f:
        f.write(chunk)

    print(f"Stored: {path}")
    return jsonify({"status": "Chunk stored"}), 200

# Download route
@app.route("/download/<file_id>", methods=["GET"])
def download(file_id):
    # Add .enc because server stores file as filename.enc
    path = f"{STORAGE_DIR}/{file_id}.enc"
    print("Looking for:", path)

    if not os.path.exists(path):
        return jsonify({"error": "File not found"}), 404

    return send_file(path, as_attachment=True)

if __name__ == "__main__":
    # Development HTTPS server (adhoc self-signed)
    app.run(ssl_context="adhoc", port=5000)