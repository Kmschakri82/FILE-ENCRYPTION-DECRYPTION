# FILE-ENCRYPTION-DECRYPTION
Built a secure tool to encrypt/decrypt files with password-derived keys, random salt/IV, padding, and integrity checks, supporting multiple file formats 
# AES File Encryption and Decryption Tool

A secure Python tool for encrypting and decrypting files using AES-256 encryption with password-derived keys. It supports all file formats and ensures data integrity.

## Features
- AES-256 (CBC mode) encryption with random salt and IV
- Password-based key derivation using PBKDF2-HMAC-SHA256
- Works with all file formats (binary-safe)
- File padding and secure decryption
- Error handling and overwrite protection

## Technologies Used
- Python 3
- cryptography library
- Built-in modules: os, hashlib, getpass, base64

## Installation
Clone the repository and install the required dependency:

```bash
git clone https://github.com/your-username/file-encryption-tool.git
cd file-encryption-tool
pip install -r requirements.txt
