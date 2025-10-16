import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import getpass

# --- Configuration ---
# Use a standard and secure key derivation function
KEY_DERIVATION_ALGORITHM = hashes.SHA256()
# Number of iterations for key stretching. Higher is more secure.
ITERATIONS = 100_000
# AES key size in bytes (256 bits = 32 bytes)
KEY_SIZE = 32
# Salt size in bytes. 16 bytes is a good standard.
SALT_SIZE = 16
# AES block size is always 128 bits (16 bytes) for this mode
BLOCK_SIZE_BYTES = 16

def derive_key(salt, password):
    """
    Derives a cryptographic key from a password and salt using PBKDF2.
    """
    kdf = PBKDF2HMAC(
        algorithm=KEY_DERIVATION_ALGORITHM,
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    """
    Encrypts a file using AES-256 GCM mode.
    GCM mode is an authenticated encryption mode, which provides both
    confidentiality and integrity.
    """
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
    except FileNotFoundError:
        print(f"Error: File not found at '{file_path}'")
        return

    # 1. Generate a cryptographically secure random salt
    salt = os.urandom(SALT_SIZE)

    # 2. Derive the encryption key from the password and salt
    key = derive_key(salt, password)

    # 3. Generate a cryptographically secure random IV (Initialization Vector)
    iv = os.urandom(BLOCK_SIZE_BYTES)

    # 4. Create the AES cipher object with GCM mode
    # GCM is an Authenticated Encryption with Associated Data (AEAD) mode.
    # It's more secure than older modes like CBC because it also ensures integrity.
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # 5. Encrypt the data
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()

    # 6. Write the salt, IV, authentication tag, and encrypted data to a new file
    # The output file will be named original_filename.enc
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as f:
        f.write(salt)
        f.write(iv)
        f.write(encryptor.tag) # GCM's authentication tag
        f.write(encrypted_data)

    print(f"✅ File encrypted successfully: '{encrypted_file_path}'")
    print("   IMPORTANT: Keep your password safe. It cannot be recovered.")

def decrypt_file(file_path, password):
    """
    Decrypts a file that was encrypted with the encrypt_file function.
    """
    try:
        with open(file_path, 'rb') as f:
            # 1. Read the salt, IV, tag, and encrypted data from the file
            salt = f.read(SALT_SIZE)
            iv = f.read(BLOCK_SIZE_BYTES)
            tag = f.read(BLOCK_SIZE_BYTES)
            encrypted_data = f.read()
    except FileNotFoundError:
        print(f"Error: Encrypted file not found at '{file_path}'")
        return
    except Exception as e:
        print(f"Error reading file. Is it a valid encrypted file? Details: {e}")
        return

    # 2. Derive the key using the same password and the extracted salt
    key = derive_key(salt, password)

    # 3. Create the AES GCM cipher for decryption
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        # 4. Decrypt the data and verify its authenticity
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # 5. Write the decrypted data to a new file
        # The output file will be named original_filename.dec
        decrypted_file_path = file_path.replace('.enc', '.dec')
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)
        
        print(f"✅ File decrypted successfully: '{decrypted_file_path}'")

    except Exception as e:
        # This exception is often raised if the password is wrong or the file is corrupt,
        # because the authentication tag will not match.
        print("❌ Decryption failed. This is likely due to an incorrect password or a corrupted file.")


def main():
    """Main function to provide a user menu."""
    while True:
        print("\n--- AES-256 File Encryption Tool ---")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            file_path = input("Enter the full path of the file to encrypt: ")
            # Use getpass to securely ask for the password without showing it on screen
            password = getpass.getpass("Enter a strong password for encryption: ")
            encrypt_file(file_path, password)
        
        elif choice == '2':
            file_path = input("Enter the full path of the file to decrypt (.enc file): ")
            password = getpass.getpass("Enter the password for decryption: ")
            decrypt_file(file_path, password)

        elif choice == '3':
            print("Exiting.")
            break
        
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()
