from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os


class EnDec:
    def __init__(self) -> None:
        self.block_size = 16

    def estimate_encrypted_size(self, data_length: int) -> int:
        data_length = (
            data_length + self.block_size - data_length % self.block_size
            or self.block_size
        )
        number_of_blocks = (data_length + self.block_size - 1) // self.block_size
        padded_data_length = number_of_blocks * self.block_size

        salt_size = 16
        iv_size = 16
        return padded_data_length + salt_size + iv_size

    def derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        return kdf.derive(password.encode())

    def encrypt_data(self, passphrase: str, data: bytes) -> bytes:
        salt = os.urandom(16)
        iv = os.urandom(16)
        key = self.derive_key(passphrase, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padding_length = (
            self.block_size - len(data) % self.block_size
        ) or self.block_size
        padded_data = data + bytes([padding_length] * padding_length)

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return salt + iv + encrypted_data

    def decrypt_data(self, passphrase: str, encrypted_data: bytes) -> bytes:
        if isinstance(encrypted_data, bytearray):
            encrypted_data = bytes(encrypted_data)

        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        actual_encrypted_data = encrypted_data[32:]

        key = self.derive_key(passphrase, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(actual_encrypted_data) + decryptor.finalize()

        padding_length = decrypted_data[-1]
        return decrypted_data[:-padding_length]
