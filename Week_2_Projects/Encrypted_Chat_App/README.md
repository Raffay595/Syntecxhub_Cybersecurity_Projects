# Encrypted Chat Application (AES + TCP)

A secure multi-client chat application built using **Python sockets** and **AES symmetric encryption**.  
All messages are encrypted before transmission and remain encrypted in server logs.

This project demonstrates practical implementation of:
- Network programming (TCP sockets)
- Symmetric encryption (AES)
- Secure IV handling
- Multi-client concurrency
- Encrypted message storage

---

## Features

- End-to-end AES encryption (client-side)  
- Secure IV generation for every message  
- TCP-based client-server communication  
- Multiple clients supported simultaneously  
- Encrypted message logging on server

---

## Encryption Design

The application uses **AES-256 in CBC mode**.

### Security Details

- **Key Size:** 256-bit AES key (derived using SHA-256)  
- **IV (Initialization Vector):** Randomly generated for every message  
- **Padding:** PKCS7 padding for block alignment  
- **Logs:** Messages stored in encrypted form on server  

> Even if the log file is accessed, messages cannot be read without the secret key.

---

## Key Handling

Currently, the system uses a **pre-shared secret key**

## How It Works

- Client encrypts message using AES

- Encrypted message is sent to server

- Server logs encrypted message

- Server broadcasts encrypted message to other clients

- Receiving client decrypts and displays it

---

## Concepts Demonstrated

**Networking**: TCP sockets, client-server model

**Cybersecurity**: AES encryption, IV handling

**Concurrency**: Threading for multiple clients

**Secure Storage**: Encrypted logging

---
