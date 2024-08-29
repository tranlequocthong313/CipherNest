from typing import Dict, List, Tuple
import threading
from .file import File


#    The structure of an LSB Embedded file header
######################################################
#        Magic String       #         Version        #
######################################################
#           Filenames        #      Embedded Sizes   #
######################################################
# Magic String: Used to identify the embedded file.
# Version: Version of the application.
# Quality: Embedding quality level (1 bit, 2 bits, 4 bits).
# Number of Files: The number of secret files embedded.
# File Metadata: Information for the secret files.
#   Filenames: Names and extensions of the files.
#   Embedded Sizes: Sizes of the embedded secret files.
class LsbHeader:
    class Props:
        def __init__(self, secret_files: File, quality="medium") -> None:
            self.secret_files = secret_files
            self.quality = quality

    def __init__(
        self,
        magic_string: str,
        version: str,
        qualities: Dict[str, int],
        block_delimiter: str,
    ) -> None:
        self.MAGIC_STRING = magic_string.encode()
        self.VERSION = version.encode()
        self.qualities = qualities
        self.block_delimiter = block_delimiter.encode()

    def length(self, props: Props) -> int:
        return len(self.make_header(props))

    def make_header(self, props: Props) -> str:
        quality = props.quality
        secret_files = props.secret_files

        if quality not in self.qualities:
            raise Exception(f"Invalid quality {quality}")

        # Convert file metadata to byte representation
        filenames_bytes = File.filenames(secret_files).encode()
        file_sizes_bytes = File.embedded_size_str(
            files=secret_files, num_bits=self.qualities[quality]
        ).encode()
        print(quality, "HEADER:::", file_sizes_bytes)

        # Build the header blocks
        header_blocks = []

        # Add MAGIC_STRING block
        header_blocks.append(self.MAGIC_STRING)

        # Add VERSION block
        version_block = (
            str(len(self.VERSION)).encode() + self.block_delimiter + self.VERSION
        )
        header_blocks.append(version_block)

        # Add FILENAMES block
        filenames_block = (
            str(len(filenames_bytes)).encode() + self.block_delimiter + filenames_bytes
        )
        header_blocks.append(filenames_block)

        # Add FILE SIZES block
        file_sizes_block = (
            str(len(file_sizes_bytes)).encode()
            + self.block_delimiter
            + file_sizes_bytes
        )
        header_blocks.append(file_sizes_block)

        return b"".join(header_blocks)

    def extract_magic_string(self, samples: List[int]) -> str:
        results = {"low": False, "medium": False, "high": False}
        threads = [
            threading.Thread(
                target=self._extract_magic_string, args=(samples, results, key)
            )
            for key in self.qualities.keys()
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        for quality in ["low", "medium", "high"]:
            if results[quality]:
                return quality
        raise ValueError("Data is not embedded by the system")

    def _extract_magic_string(
        self, samples: List[int], results: Dict[str, Tuple[int, int]], quality: str
    ):
        lsb = self.qualities[quality]
        end_magic_str_index = self.magic_str_index(quality)

        bits = ""
        for i in range(end_magic_str_index):
            extracted_bits = samples[i] & ((1 << lsb) - 1)
            bits += format(extracted_bits, f"0{lsb}b")

        magic_string = ""
        for i in range(0, len(bits), 8):
            byte = bits[i : i + 8]
            magic_string += chr(int(byte, 2))

        if magic_string.encode() == self.MAGIC_STRING:
            results[quality] = True

    def extract_header_blocks(self, samples: List[int], quality: str, start_index: int):
        blocks = {}
        total_blocks = 3  # Số lượng blocks mà bạn muốn trích xuất
        block_names = ["VERSION", "FILENAMES", "EMBEDDED_SIZES"]
        index = start_index

        while len(blocks) < total_blocks:
            index = self.search_for_block(samples, block_names, blocks, quality, index)

        return {**blocks, "index": index}

    def search_for_block(
        self,
        samples: List[int],
        block_names: List[str],
        blocks: Dict[str, str],
        quality: str,
        start_index: int = 0,
    ):
        lsb = self.qualities[quality]
        index = start_index
        bits = ""
        byte_str = ""
        content_start_index = 0
        length = 0

        # 1. Đọc và trích xuất length
        for i in range(index, len(samples)):
            extracted_bits = samples[i] & ((1 << lsb) - 1)
            bits += format(extracted_bits, f"0{lsb}b")

            if len(bits) == 8:
                current_byte = chr(int(bits, 2))
                bits = ""
                byte_str += current_byte
                delimiter_str = byte_str[-len(self.block_delimiter) :]
                if delimiter_str.encode() == self.block_delimiter:
                    length = int(byte_str[: -len(self.block_delimiter)])
                    content_start_index = i + 1
                    break

        # 3. Đọc và trích xuất content dựa trên length đã tìm được
        content_bits = ""
        length = length * 8 // lsb
        for i in range(content_start_index, content_start_index + length):
            extracted_bits = samples[i] & ((1 << lsb) - 1)
            content_bits += format(extracted_bits, f"0{lsb}b")

        block_content = ""
        for i in range(0, len(content_bits), 8):
            byte = content_bits[i : i + 8]
            block_content += chr(int(byte, 2))

        blocks[block_names[len(blocks)]] = block_content

        # Trả về chỉ mục tiếp theo sau khi đã xử lý xong block hiện tại
        return content_start_index + length

    def magic_str_index(self, quality: str) -> int:
        lsb = self.qualities[quality]
        return len(self.MAGIC_STRING) * 8 // lsb
