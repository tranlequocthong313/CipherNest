from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os


# Encryption/Decryption
class EnDec:
    def __init__(self) -> None:
        self.salt = os.urandom(16)
        self.iv = os.urandom(16)

    def derive_key(self, password: str, salt: bytes) -> bytes:
        # Sử dụng PBKDF2 để tạo key từ password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Độ dài của key là 256 bit (32 bytes)
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        key = kdf.derive(password.encode())
        return key

    def decrypt_data(self, password: str, encrypted_data: bytes) -> bytes:
        try:
            # Lấy key từ password sử dụng salt
            key = self.derive_key(password, self.salt)

            # Tạo Cipher để decrypt
            cipher = Cipher(
                algorithms.AES(key), modes.CBC(self.iv), backend=default_backend()
            )
            decryptor = cipher.decryptor()

            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

            # Remove padding
            padding_length = decrypted_data[-1]
            unpadded_data = decrypted_data[:-padding_length]

            return unpadded_data

        except ValueError as e:
            # Handle invalid key or padding errors
            print("Decryption failed:", e)
            raise ValueError("Decryption failed. Invalid key or corrupted data.")
        except Exception as e:
            # Handle other potential errors
            print("An error occurred during decryption:", e)
            raise ValueError("Decryption failed due to an unknown error.")

    def estimate_encrypted_size(self, data_length: int, block_size: int = 16) -> int:
        # Tính toán số block cần thiết để chứa toàn bộ dữ liệu
        number_of_blocks = (data_length + block_size - 1) // block_size
        estimated_size = number_of_blocks * block_size
        return estimated_size

    def derive_key_from_passphrase(
        self, passphrase: str, salt: bytes, length: int = 32
    ) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        key = kdf.derive(passphrase.encode())
        return key

    def encrypt_data(self, key: str, data: bytes) -> bytes:
        key = self.derive_key_from_passphrase(key, self.salt)
        cipher = Cipher(
            algorithms.AES(key), modes.CBC(self.iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()

        padding_length = (16 - len(data) % 16) % 16
        padded_data = data + bytes([padding_length] * padding_length)

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return encrypted_data
