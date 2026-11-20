import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# MSc CONCEPTS IN THIS FILE:
# AES-256-GCM = Symmetric encryption + authentication
# PBKDF2 = Password -> Strong Key, with 600k iterations to slow hackers
# Salt = random 16 bytes, makes same password = different key every time
# Nonce = random 12 bytes, makes same file = different ciphertext every time

def get_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits = AES-256
        salt=salt,
        iterations=600000,  # OWASP recommendation
    )
    return kdf.derive(password.encode())

def encrypt_file(input_path, output_path, password):
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = get_key(password, salt)
    aesgcm = AESGCM(key)

    with open(input_path, 'rb') as f:
        plaintext = f.read()

    # AESGCM encrypts AND creates an authentication tag.
    # If 1 bit is changed, decryption will FAIL. That's GCM.
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # File format: [salt 16][nonce 12][ciphertext]
    with open(output_path, 'wb') as f:
        f.write(salt + nonce + ciphertext)
    print(f"✅ Encrypted: {input_path} -> {output_path}")

def decrypt_file(input_path, output_path, password):
    with open(input_path, 'rb') as f:
        data = f.read()

    salt = data[:16]
    nonce = data[16:28]
    ciphertext = data[28:]

    key = get_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        print(f"✅ Decrypted: {input_path} -> {output_path}")
    except Exception:
        print("❌ WRONG PASSWORD or file has been tampered with!")

print("=== SecureVault - MSc Cryptography Project ===")
print("1. Encrypt a file")
print("2. Decrypt a file")
choice = input("Choose 1 or 2: ")

if choice == "1":
    inp = input("File to encrypt (e.g. notes.txt): ")
    out = input("Output name (e.g. notes.txt.enc): ")
    pwd = input("Set a strong password: ")
    encrypt_file(inp, out, pwd)
elif choice == "2":
    inp = input("File to decrypt (e.g. notes.txt.enc): ")
    out = input("Output name (e.g. notes_decrypted.txt): ")
    pwd = input("Enter password: ")
    decrypt_file(inp, out, pwd)