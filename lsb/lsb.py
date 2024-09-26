import time
from typing import List
import threading

from utils.exceptions import (
    DataCorruptedError,
    RequirePasswordError,
    RunOutOfFreeSpaceError,
    WrongPasswordError,
)
from lsb.models import ExtractedPayload
from .file import File
from .header import LsbHeader
from CipherNest import settings


class LSBSteganography:
    def __init__(self):
        self.secret_key = settings.SECRET_KEY
        self.qualities = {"low": 4, "medium": 2, "high": 1, "very_low": 8}
        self.header = LsbHeader(
            magic_string="CipherNest",
            version="1.0",
            qualities=self.qualities,
            block_delimiter="BLK",
            secret_key=self.secret_key,
        )

    def get_free_space(
        self,
        samples: List[int],
        secret_files: List[File],
        quality: str = "medium",
        compressed: bool = False,
        passphrase: str = None,
    ) -> int:
        if quality not in self.qualities:
            raise ValueError(f"Invalid quality {quality}")
        bits_per_sample = self.qualities[quality]

        total_samples = len(samples)
        header_length = self.header.length(
            LsbHeader.Props(
                secret_files=secret_files,
                quality=quality,
                compressed=compressed,
                passphrase=passphrase,
            )
        )
        total_secret_file_size = File.total_size(files=secret_files)
        return (
            ((total_samples * bits_per_sample) // 8) - header_length - total_secret_file_size
        )

    def is_embedded(self, samples: List[int]) -> bool:
        try:
            return self.header.get_quality_from_embedded_data(samples) is not None
        except ValueError:
            return False

    def embed(
        self,
        samples: List[int],
        secret_files: List[bytes],
        quality: str = "medium",
        compressed: bool = False,
        passphrase: str = None,
    ):
        free_space = self.get_free_space(
            samples=samples,
            secret_files=secret_files,
            quality=quality,
            compressed=compressed,
            passphrase=passphrase,
        )
        lsb = self.qualities[quality]

        if free_space < 0:
            raise RunOutOfFreeSpaceError()

        header = self.header.make_header(
            LsbHeader.Props(
                secret_files=secret_files,
                quality=quality,
                compressed=compressed,
                passphrase=passphrase,
            )
        )

        current_index = self.embed_data(samples, header, lsb, start_index=0)

        self.embed_data_singlethread(
            samples=samples,
            secret_files=secret_files,
            lsb=lsb,
            start_index=current_index,
            compressed=compressed,
            passphrase=passphrase,
        )

    def embed_data(
        self, samples: List[int], data: bytes, lsb: int, start_index=0
    ) -> int:
        end_index = len(data) * 8 // lsb + start_index
        data_index = 0
        bit_index = 0
        for i in range(start_index, end_index):
            if data_index >= len(data):
                break
            byte_to_embed = data[data_index]
            bits_in_data_index = 8 - lsb - bit_index
            bits_to_embed = (byte_to_embed >> bits_in_data_index) & ((1 << lsb) - 1)
            samples[i] = (samples[i] & ~((1 << lsb) - 1)) | bits_to_embed
            bit_index += lsb
            if bit_index >= 8:
                bit_index = 0
                data_index += 1
        return end_index

    def embed_data_multithread(
        self,
        samples: List[int],
        secret_files: List[bytes],
        lsb: int,
        start_index=0,
        compressed: bool = False,
        passphrase: str = None,
    ) -> int:
        num_threads = len(secret_files)
        thread_list = []
        chunk_size = len(samples) // num_threads

        def embed_part(thread_id, secret_file):
            part_start = start_index + thread_id * chunk_size
            self.embed_data(
                samples=samples,
                data=self._get_data(secret_file, compressed, passphrase),
                lsb=lsb,
                start_index=part_start,
            )

        start_time = time.time()  # Start timing
        for i, secret_file in enumerate(secret_files):
            thread = threading.Thread(target=embed_part, args=(i, secret_file))
            thread_list.append(thread)
            thread.start()

        for thread in thread_list:
            thread.join()
        end_time = time.time()  # End timing
        print(
            f"Execution time with multithreading: {end_time - start_time:.6f} seconds"
        )

        return start_index + chunk_size * num_threads

    def embed_data_singlethread(
        self,
        samples: List[int],
        secret_files: List[bytes],
        lsb: int,
        start_index=0,
        compressed: bool = False,
        passphrase: str = None,
    ) -> int:
        start_time = time.time()  # Start timing
        for secret_file in secret_files:
            start_index = self.embed_data(
                samples=samples,
                data=self._get_data(secret_file, compressed, passphrase),
                lsb=lsb,
                start_index=start_index,
            )
        end_time = time.time()  # End timing
        print(f"Execution time with single thread: {end_time - start_time:.6f} seconds")

        return start_index

    def _get_data(self, file: File, compressed: bool = False, passphrase: str = None):
        if compressed and passphrase:
            return file.compress_encrypt(passphrase)
        elif passphrase:
            return file.encrypt(passphrase)
        elif compressed:
            return file.compressed_data
        return file.raw_data

    def get_header_blocks(self, samples: List[int], passphrase: str = None) -> dict:
        quality = self.header.get_quality_from_embedded_data(
            samples, raise_exception=False
        )
        if not quality:
            return None
        start_index = self.header.magic_str_index(quality)
        header_blocks = self.header.extract_header_blocks(samples, quality, start_index)
        print('HEADER BLOCKS:::', header_blocks)
        is_encrypted = header_blocks["EF"] == "1"
        if is_encrypted and passphrase is None:
            raise RequirePasswordError()
        passphrase = passphrase or self.secret_key
        if self.header.verify_hmac(key=passphrase, header_blocks=header_blocks) is True:
            return header_blocks
        if is_encrypted:
            raise WrongPasswordError()
        raise DataCorruptedError()

    def extract_data(self, samples: List[int], passphrase: str = None) -> ExtractedPayload:
        start_time = time.time()  # Start timing
        
        quality = self.header.get_quality_from_embedded_data(samples)
        start_index = self.header.magic_str_index(quality)
        blocks = self.header.extract_header_blocks(samples, quality, start_index)

        true, false = "1", "0"
        ef = blocks["EF"] is true
        if ef and passphrase is None:
            raise RequirePasswordError()
        
        passphrase = passphrase or self.secret_key
        if not self.header.verify_hmac(passphrase, blocks):
            if ef:
                raise WrongPasswordError()
            else:
                raise DataCorruptedError()

        sizes = File.str_sizes_to_array(blocks["EMBEDDED_SIZES"])
        filenames = File.str_filenames_to_array(blocks["FILENAMES"])
        start_index = blocks["index"]
        
        extracted_files = []
        for i in range(min(len(sizes), len(filenames))):
            data = self._extract_data(samples, quality, start_index, sizes[i])
            extracted_files.append((filenames[i], data))
            start_index = start_index + sizes[i]

        end_time = time.time()
        print(f"Execution time: {end_time - start_time:.6f} seconds")

        return ExtractedPayload(metadata=blocks, extracted_files=extracted_files)

    def _extract_data(self, samples: List[int], quality, start_index, end_index):
        lsb = self.qualities[quality]
        bits = []
        for i in range(start_index, start_index + end_index):
            extracted_bits = samples[i] & ((1 << lsb) - 1)
            bits.append(format(extracted_bits, f"0{lsb}b"))

        bits_str = "".join(bits)

        data_bytes = bytearray()
        for i in range(0, len(bits_str), 8):
            byte = bits_str[i : i + 8]
            data_bytes.append(int(byte, 2))

        return data_bytes
