import os
import getpass
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode, urlsafe_b64decode

class AESFileEncryptor:
    def __init__(self, password: str, salt: bytes = None):
        if salt is None:
            salt = os.urandom(16)  # Random salt for each session
        self.salt = salt

        # Derive key from password using PBKDF2HMAC (SHA256)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        self.key = kdf.derive(password.encode())

    def encrypt(self, inpfile: str, outfile: str):
        try:
            with open(inpfile, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            print(f"❌ Error: File '{inpfile}' not found!")
            return

        # Add padding (AES requires data multiple of block size 16)
        padding_len = 16 - (len(data) % 16)
        data += bytes([padding_len]) * padding_len

        # Generate random IV
        iv = os.urandom(16)

        # Encrypt
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        # Store salt + iv + encrypted data
        with open(outfile, "wb") as f:
            f.write(self.salt + iv + encrypted_data)

        print(f"✅ File '{inpfile}' encrypted successfully into '{outfile}'.")

    def decrypt(self, inpfile: str, outfile: str, password: str):
        try:
            with open(inpfile, "rb") as f:
                file_data = f.read()
        except FileNotFoundError:
            print(f"❌ Error: File '{inpfile}' not found!")
            return

        salt = file_data[:16]
        iv = file_data[16:32]
        encrypted_data = file_data[32:]

        # Re-derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove padding
        padding_len = decrypted_data[-1]
        decrypted_data = decrypted_data[:-padding_len]

        with open(outfile, "wb") as f:
            f.write(decrypted_data)

        print(f"✅ File '{inpfile}' decrypted successfully into '{outfile}'.")

if __name__ == "__main__":
    while True:
        print("\n--- AES File Encryption & Decryption Tool ---")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Exit")

        choice = input("Enter choice: ")

        if choice == "1":
            password = getpass.getpass("Enter password: ")
            encryptor = AESFileEncryptor(password=password)

            infile = input("Enter input file name: ")
            outfile = input("Enter output file name: ")
            encryptor.encrypt(infile, outfile)

        elif choice == "2":
            password = getpass.getpass("Enter password: ")
            infile = input("Enter encrypted file name: ")
            outfile = input("Enter output file name: ")

            decryptor = AESFileEncryptor(password=password)  # dummy init
            decryptor.decrypt(infile, outfile, password)

        elif choice == "3":
            print("👋 Exiting program.")
            break
        else:
            print("❌ Invalid choice! Try again.")
