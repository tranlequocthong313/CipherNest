import os
from typing import List
import wave
from .utils.codec import CoDec
from .utils.endec import EnDec

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
            # if "wav" in path:
            #     with wave.open(path, "rb") as file:
            #         nframes = file.getnframes()
            #         frames = file.readframes(nframes)
            #         frame_list = list(frames)
            #         self.raw_data = frame_list
            #         self.params = file.getparams()
            # else:
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
    def filenames(files: List["File"], delimiter: str = "/") -> List[str]:
        file_names = [file.name for file in files]
        return delimiter.join(file_names)

    @staticmethod
    def file_sizes(files: List["File"], delimiter: str = "/") -> List[str]:
        sizes = [str(file.size) for file in files]
        return delimiter.join(sizes)

    @staticmethod
    def compressed_file_sizes(files: List["File"], delimiter: str = "/") -> List[str]:
        sizes = [str(file.compressed_size) for file in files]
        return delimiter.join(sizes)

    @staticmethod
    def embedded_size_str(
        files: List["File"], num_bits: int = 2, delimiter: str = "/"
    ) -> List[str]:
        # bits = 8
        # sizes = [str(file.size * bits // num_bits) for file in files]
        sizes = [
            str(
                File.proc_estimate_embedded_size_after_encrypting(
                    # file.compressed_size, num_bits
                    "2525",
                    file.compressed_data,
                    num_bits,
                )
            )
            for file in files
        ]
        return delimiter.join(sizes)

    @staticmethod
    def embedded_compressed_size_str(
        files: List["File"], num_bits: int = 2, delimiter: str = "/"
    ) -> List[str]:
        bits = 8
        sizes = [str(file.compressed_size * bits // num_bits) for file in files]
        return delimiter.join(sizes)

    @staticmethod
    def arr_filenames(filenamesStr: str, delimiter: str = "/") -> List[str]:
        return filenamesStr.split(delimiter)

    @staticmethod
    def arr_file_sizes(sizesStr: str, delimiter: str = "/") -> List[int]:
        return [int(size) for size in sizesStr.split(delimiter)]

    @staticmethod
    def embeddable(files: List["File"], free_space: int, num_bits: int = 2) -> bool:
        for file in files:
            # if file.embedded_size(num_bits) > free_space:
            if file.estimate_embedded_size_after_encrypting(num_bits) > free_space:
                return False
        return True

    def embedded_size(self, num_bits: int = 2) -> int:
        bits = 8
        return self.size * (bits // num_bits)

    def encrypt(self, passphrase: str) -> bytes:
        print("ENCRYPTED SIZE:::", len(endec.encrypt_data(passphrase, self.raw_data)))
        return endec.encrypt_data(passphrase, self.raw_data)

    def compress_encrypt(self, passphrase: str) -> bytes:
        print(
            "COMPRESSED_ENCRYPTED SIZE:::",
            len(endec.encrypt_data(passphrase, self.compressed_data)),
        )
        return endec.encrypt_data(passphrase, self.compressed_data)

    @staticmethod
    def decrypt(passphrase: str, encrypted_data: bytes) -> bytes:
        print("DECRYPTED SIZE:::", len(endec.encrypt_data(passphrase, encrypted_data)))
        return endec.decrypt_data(passphrase, encrypted_data)

    @staticmethod
    def decompress_decrypt(passphrase: str, encrypted_data: bytes) -> bytes:
        decrypted_data = endec.decrypt_data(passphrase, encrypted_data)
        print("DECRYPTED DATA:::", decrypted_data[:100])
        decompress_data = codec.decompress_data(decrypted_data)
        print(
            "DECOMPRESS_DECRYPTED SIZE:::",
            len(codec.decompress_data(decrypted_data)),
        )
        return decompress_data

    def estimate_embedded_size_after_encrypting(self, num_bits: int = 2) -> int:
        print("ACTUAL_SIZE:::", self.compressed_size)
        print(
            "ESTIMATED_SIZE:::",
            File.proc_estimate_embedded_size_after_encrypting(
                # self.compressed_size, num_bits
                "2525",
                self.compressed_data,
                num_bits,
            ),
        )
        return File.proc_estimate_embedded_size_after_encrypting(
            # self.compressed_size, num_bits
            "2525",
            self.compressed_data,
            num_bits,
        )

    @staticmethod
    def proc_estimate_embedded_size_after_encrypting(
        # actual_size: int, num_bits: int = 2
        passphrase,
        data: bytes,
        num_bits: int = 2,
    ) -> int:
        bits = 8
        # size = endec.estimate_encrypted_size(actual_size)
        size = len(endec.encrypt_data(passphrase, data))
        return size * bits // num_bits
