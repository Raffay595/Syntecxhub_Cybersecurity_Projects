# Encrypted File Transfer & Secure File Storage

## Project Overview
This project implements a **secure system for file transfer and storage** between a client and a server. It ensures **confidentiality, integrity, and safe retrieval** of files using modern cryptographic techniques.

Key features include:
- **Encrypted file upload and download** using AES over a secure channel.
- **Chunking large files** to support efficient transfer.
- **Integrity checks** using HMAC to detect tampering.
- **Optional resume support** for interrupted transfers.
- **Encrypted file storage** on the server to protect at rest.

---

## Features

### 1. Encrypted Transfer
- Files are encrypted using **AES (Advanced Encryption Standard)**.
- Communication occurs over a **secure channel** (TLS/SSL recommended).
- Ensures that eavesdroppers cannot read file contents.

### 2. Chunked File Upload
- Large files are split into smaller chunks.
- Each chunk is encrypted individually.
- Supports **resume capability** for interrupted transfers (optional).

### 3. Integrity Verification
- **HMAC (Hash-based Message Authentication Code)** is computed for each chunk.
- The server verifies HMAC before writing data to disk.
- Protects against **data tampering** during transfer.

### 4. Secure Storage
- Files are **stored encrypted on the server disk**.
- Only authorized clients can retrieve and decrypt files.
- Prevents unauthorized access even if the server is compromised.

---

## Threat Model & Mitigation

| Threat | Mitigation |
|--------|------------|
| **Man-in-the-middle attack (MITM)** | Use TLS/SSL for all client-server communications. Validate server certificates. |
| **Key leakage** | Generate strong AES keys per session or file. Avoid storing keys in plaintext on server. Use secure key exchange (e.g., Diffie-Hellman). |
| **Data tampering** | Apply HMAC checks for each file chunk to detect modifications. |
| **Unauthorized access to stored files** | Store all files encrypted on disk. Restrict access with server authentication. |

---

## Security Considerations

- Always use strong passwords or keys.
- Ensure TLS certificates are valid to prevent MITM attacks.
- Regularly audit and rotate encryption keys if stored server-side.
- Validate file integrity after transfer to prevent silent corruption.
