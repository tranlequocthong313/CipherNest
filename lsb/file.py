import os
from typing import List
from utils.codec import CoDec
from utils.endec import EnDec

codec = CoDec()
endec = EnDec()


class File:
    def __init__(
        self, path: str = None, name: str = None, size: int = None, data: bytes = None
    ) -> None:
        self._compressed_data = None
        self._compressed_size = None
        if path:
            self.name = os.path.basename(path)
            self.size = os.path.getsize(path)
            with open(path, "rb") as file:
                self.raw_data = file.read()
        elif name and size is not None and data is not None:
            self.name = name
            self.size = size
            self.raw_data = data
        else:
            raise ValueError("Invalid arguments provided for initialization")

    @property
    def compressed_data(self):
        if self._compressed_data:
            return self._compressed_data
        self._compressed_data = codec.compress_data(self.raw_data)
        return self._compressed_data

    @property
    def compressed_size(self):
        if self._compressed_size:
            return self._compressed_size
        self._compressed_size = len(self.compressed_data)
        return self._compressed_size

    @staticmethod
    def filenames_with_delimiter(files: List["File"], delimiter: str = "/") -> List[str]:
        file_names = [file.name for file in files]
        return delimiter.join(file_names)

    @staticmethod
    def file_sizes_with_delimiter(files: List["File"], delimiter: str = "/") -> List[str]:
        sizes = [str(file.size) for file in files]
        return delimiter.join(sizes)

    @staticmethod
    def embedded_sizes_with_delimiter(
        files: List["File"],
        num_bits: int = 2,
        delimiter: str = "/",
        compressed=False,
        passphrase: str = None,
    ) -> List[str]:
        sizes = [
            str(
                File.estimate_embedded_size_handler(
                    passphrase=passphrase,
                    data=file.compressed_data if compressed else file.raw_data,
                    num_bits=num_bits,
                )
            )
            for file in files
        ]
        return delimiter.join(sizes)

    @staticmethod
    def str_filenames_to_array(filenamesStr: str, delimiter: str = "/") -> List[str]:
        return filenamesStr.split(delimiter)

    @staticmethod
    def str_sizes_to_array(sizesStr: str, delimiter: str = "/") -> List[int]:
        return [int(size) for size in sizesStr.split(delimiter)]

    def embedded_size(self, num_bits: int = 2) -> int:
        bits = 8
        return self.size * (bits // num_bits)

    def encrypt(self, passphrase: str) -> bytes:
        return endec.encrypt_data(passphrase, self.raw_data)

    def compress_encrypt(self, passphrase: str) -> bytes:
        return endec.encrypt_data(passphrase, self.compressed_data)

    @staticmethod
    def decrypt(passphrase: str, encrypted_data: bytes) -> bytes:
        return endec.decrypt_data(passphrase, encrypted_data)

    @staticmethod
    def decompress_decrypt(passphrase: str, encrypted_compressed_data: bytes) -> bytes:
        decrypted_data = endec.decrypt_data(passphrase, encrypted_compressed_data)
        decompress_data = codec.decompress_data(decrypted_data)
        return decompress_data

    @staticmethod
    def decompress(compressed_data: bytes) -> bytes:
        decompress_data = codec.decompress_data(compressed_data)
        return decompress_data

    def estimate_embedded_size(
        self, num_bits: int = 2, compressed: bool = False, passphrase: str = None
    ) -> int:
        return File.estimate_embedded_size_handler(
            data=self.compressed_data if compressed else self.raw_data,
            passphrase=passphrase,
            num_bits=num_bits,
        )

    @staticmethod
    def estimate_embedded_size_handler(
        data: bytes,
        passphrase: str = None,
        num_bits: int = 2,
    ) -> int:
        bits = 8
        if passphrase:
            size = endec.estimate_encrypted_size(data_length=len(data))
        else:
            size = len(data)
        return size * bits // num_bits

    @staticmethod
    def total_size(files: List["File"]) -> int:
        return sum(file.size for file in files)
