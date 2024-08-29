import time
from typing import Dict, List
import threading
from .file import File
from .header import LsbHeader


class LSBSteganography:
    def __init__(self):
        self.qualities = {"low": 4, "medium": 2, "high": 1}
        self.header = LsbHeader(
            magic_string="CipherNest",
            version="1.0",
            qualities=self.qualities,
            block_delimiter="BLK",
        )

    def make_header(self, secret_files: List[File], quality: str = "medium") -> str:
        return self.header.make_header(
            LsbHeader.Props(secret_files=secret_files, quality=quality)
        )

    def extract_header_blocks(
        self, header_data: str
    ) -> Dict[str, str | List[str | int]]:
        return self.header.extract_header_blocks(header_data)

    def get_free_space(
        self,
        samples: List[int],
        secret_files: List[File],
        quality: str = "medium",
    ) -> int:
        if quality not in self.qualities:
            raise Exception(f"Invalid quality {quality}")
        bits_per_sample = self.qualities[quality]

        total_samples = len(samples)
        free_space = ((total_samples * bits_per_sample) // 8) - self.header.length(
            LsbHeader.Props(secret_files=secret_files, quality=quality)
        )
        return free_space

    def is_embedded(self) -> bool:
        pass

    def extract_secrets(self):
        pass

    def needs_password(self) -> bool:
        pass

    def embed(
        self,
        samples: List[int],
        secret_files: List[bytes],
        quality: str = "medium",
    ) -> List[int]:
        free_space = self.get_free_space(samples, secret_files, quality)
        lsb = self.qualities[quality]

        if not File.embeddable(secret_files, free_space, num_bits=lsb):
            raise Exception("Not enough free space")

        header = self.header.make_header(
            LsbHeader.Props(secret_files=secret_files, quality=quality)
        )

        current_index = self.embed_data(samples, header, lsb, start_index=0)

        self.embed_data_singlethread(
            samples, secret_files, lsb, start_index=current_index
        )

        return samples

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
        self, samples: List[int], secret_files: List[bytes], lsb: int, start_index=0
    ) -> int:
        num_threads = len(secret_files)
        thread_list = []
        chunk_size = len(samples) // num_threads

        def embed_part(thread_id, secret_file):
            part_start = start_index + thread_id * chunk_size
            # self.embed_data(samples, secret_file.raw_data, lsb, start_index=part_start)
            self.embed_data(
                samples,
                # secret_file.encrypt(passphrase="2525"),
                secret_file.compress_encrypt(passphrase="2525"),
                lsb,
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
        self, samples: List[int], secret_files: List[bytes], lsb: int, start_index=0
    ) -> int:
        start_time = time.time()  # Start timing
        for secret_file in secret_files:
            # start_index = self.embed_data(
            #     samples, secret_file.raw_data, lsb, start_index
            # )
            start_index = self.embed_data(
                # samples, secret_file.encrypt("2525"), lsb, start_index
                samples,
                secret_file.compress_encrypt("2525"),
                lsb,
                start_index,
            )
        end_time = time.time()  # End timing
        print(f"Execution time with single thread: {end_time - start_time:.6f} seconds")

        return start_index

    def extract_data(self, samples: List[int]) -> List:
        quality = self.header.extract_magic_string(samples)
        start_index = self.header.magic_str_index(quality)
        blocks = self.header.extract_header_blocks(samples, quality, start_index)
        sizes = File.arr_file_sizes(blocks["EMBEDDED_SIZES"])
        filenames = File.arr_filenames(blocks["FILENAMES"])
        start_index = blocks["index"]
        results = []
        for i in range(min(len(sizes), len(filenames))):
            data = self._extract_data(samples, quality, start_index, sizes[i])
            results.append((filenames[i], data))
            start_index = start_index + sizes[i]
        return results

    def _extract_data(self, samples: List[int], quality, start_index, end_index):
        lsb = self.qualities[quality]
        bits = []
        for i in range(start_index, start_index + end_index):
            extracted_bits = samples[i] & ((1 << lsb) - 1)
            bits.append(format(extracted_bits, f"0{lsb}b"))

        # Kết nối tất cả các bits lại thành chuỗi
        bits_str = "".join(bits)

        # Chuyển đổi chuỗi các bits thành bytes
        data_bytes = bytearray()
        for i in range(0, len(bits_str), 8):
            byte = bits_str[i : i + 8]
            data_bytes.append(int(byte, 2))

        return data_bytes
