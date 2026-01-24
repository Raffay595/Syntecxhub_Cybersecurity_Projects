# Local Encrypted Password Manager

A secure local password manager built in Python that stores credentials in an encrypted format on disk. This project focuses on strong cryptography, secure key handling, and safe local storage practices.

## Features

- Master password authentication
- Strong symmetric encryption (AES)
- Secure storage using encrypted JSON
- Add new credentials
- Retrieve saved credentials
- Delete stored entries
- Search for saved accounts
- Protection against plain-text password storage

## Concepts Learned

- Symmetric encryption (AES)
- Secure key derivation and handling
- Password-based authentication
- JSON data storage
- File encryption and decryption
- Secure coding practices in Python

## Security Design

- All credentials are stored in an **encrypted file**
- A **master password** is required to unlock the vault
- Encryption ensures passwords are never stored in plain text
- Even if the file is stolen, data remains unreadable without the key

## Storage Format

Passwords are saved in an **encrypted JSON structure** like:

```json
{
  "gmail.com": {
    "username": "user@gmail.com",
    "password": "encrypted_value"
  }
}
