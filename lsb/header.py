from typing import Dict, List, Tuple
import threading

from utils.exceptions import NotEmbeddedBySystemError
from .file import File
import hmac
import hashlib


"""
               The structure of an Embedded File's Header
        ######################################################
        #     Magic String      # CF # EF #      Version     #
        ######################################################
        #             Filenames         #   Embedded Sizes   #
        ######################################################
        #                        HMAC                        #  
        ######################################################

- Magic String: A unique identifier used to recognize the presence of an embedded file in the data stream.
- CF (Compression Flag): Indicates whether the secret data has been compressed before embedding (1 if compressed, 0 otherwise).
- EF (Encryption Flag): Indicates whether the secret data has been encrypted (1 if encrypted, 0 otherwise).
- Version: Version number of the steganography application or the embedding format being used.
- File Metadata: Information related to the embedded secret files, including filenames and their respective sizes.
   + Filenames: The names and file extensions of the secret files that have been embedded.
   + Embedded Sizes: The sizes (in bytes) of the embedded secret files to help extract the correct amount of data during retrieval.
- HMAC: A Hash-based Message Authentication Code used to verify the integrity and authenticity of the embedded data. It ensures that the data has not been altered or tampered with.
"""


class LsbHeader:
    class Props:
        def __init__(
            self,
            secret_files: list[File],
            quality: str = "medium",
            compressed: bool = False,
            passphrase: str = None,
        ) -> None:
            self.secret_files = secret_files
            self.quality = quality
            self.compressed = compressed
            self.passphrase = passphrase

    def __init__(
        self,
        magic_string: str,
        version: str,
        qualities: Dict[str, int],
        block_delimiter: str,
        secret_key: str,
    ) -> None:
        self.MAGIC_STRING = magic_string.encode()
        self.VERSION = version.encode()
        self.qualities = qualities
        self.block_delimiter = block_delimiter.encode()
        self.secret_key = secret_key
        self.block_names = [
            "CF",
            "EF",
            "VERSION",
            "FILENAMES",
            "EMBEDDED_SIZES",
            "HMAC",
        ]
        self.full_block_names = ["MAGIC_STRING", *self.block_names]

    def length(self, props: Props) -> int:
        return len(self.make_header(props))

    def make_header(self, props: Props) -> str:
        quality = props.quality
        secret_files = props.secret_files
        if quality not in self.qualities:
            raise ValueError(f"Invalid quality {quality}")
        if secret_files and isinstance(secret_files, list) is False:
            raise ValueError("Secret files must be array or None")

        passphrase = props.passphrase
        compressed = props.compressed
        secret_files = props.secret_files
        filenames_bytes = File.filenames_with_delimiter(secret_files).encode()
        file_sizes_bytes = File.embedded_sizes_with_delimiter(
            files=secret_files,
            num_bits=self.qualities[quality],
            compressed=compressed,
            passphrase=passphrase,
        ).encode()

        # Build the header blocks
        header_blocks = [self.MAGIC_STRING]

        boolean_length = 1
        true, false = "1", "0"
        cf_flag = true if compressed else false
        ef_flag = true if passphrase is not None else false

        # Add CF block
        cf_block = (
            str(boolean_length).encode() + self.block_delimiter + cf_flag.encode()
        )
        header_blocks.append(cf_block)
        # Add EF block
        ef_block = (
            str(boolean_length).encode() + self.block_delimiter + ef_flag.encode()
        )
        header_blocks.append(ef_block)
        # Add VERSION block
        version_block = (
            str(len(self.VERSION)).encode() + self.block_delimiter + self.VERSION
        )
        header_blocks.append(version_block)
        checksum_blocks = [cf_flag.encode(), ef_flag.encode(), self.VERSION]

        # Add FILENAMES block
        filenames_block = str(len(filenames_bytes)).encode() + self.block_delimiter + filenames_bytes
        header_blocks.append(filenames_block)
        checksum_blocks.append(filenames_bytes)

        # Add FILESIZES block
        file_sizes_block = str(len(file_sizes_bytes)).encode() + self.block_delimiter + file_sizes_bytes
        header_blocks.append(file_sizes_block)
        checksum_blocks.append(file_sizes_bytes)

        checksum_data = b"".join(checksum_blocks)

        hmac_key = passphrase.encode() if passphrase else self.secret_key.encode()
        hmac_value = hmac.new(hmac_key, checksum_data, hashlib.sha256).digest()

        # Add HMAC block
        hmac_block = str(len(hmac_value)).encode() + self.block_delimiter + hmac_value
        header_blocks.append(hmac_block)

        return b"".join(header_blocks)

    def verify_hmac(
        self,
        key: str,
        header_blocks: dict,
    ) -> bool:
        checksum_data = b""
        extracted_hmac = header_blocks["HMAC"]
        for block_name in self.block_names:
            if block_name in header_blocks and block_name != "HMAC":
                block_data = header_blocks[block_name]
                if isinstance(block_data, bytes):
                    checksum_data += block_data
                else:
                    checksum_data += block_data.encode()

        hmac_key = key.encode() or self.secret_key.encode()
        calculated_hmac = hmac.new(hmac_key, checksum_data, hashlib.sha256).digest()
        return hmac.compare_digest(extracted_hmac, calculated_hmac)

    def get_quality_from_embedded_data(
        self, samples: List[int], raise_exception: bool = False
    ) -> str:
        results = {key: False for key in self.qualities}
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
        for quality in list(self.qualities.keys()):
            if results[quality]:
                return quality

        if raise_exception:
            raise NotEmbeddedBySystemError()
        return None

    def _extract_magic_string(
        self, samples: List[int], results: Dict[str, Tuple[int, int]], quality: str
    ):
        lsb = self.qualities[quality]
        end_magic_str_index = self.magic_str_index(quality)

        if end_magic_str_index > len(samples):
            return

        bits = ""
        for i in range(end_magic_str_index):
            extracted_bits = samples[i] & ((1 << lsb) - 1)
            bits += format(extracted_bits, f"0{lsb}b")

        magic_string = "".join(
            chr(int(bits[i : i + 8], 2)) for i in range(0, len(bits), 8)
        )
        if magic_string.encode() == self.MAGIC_STRING:
            results[quality] = True

    def extract_header_blocks(self, samples: List[int], quality: str, start_index: int):
        blocks = {}
        total_blocks = len(self.block_names)
        index = start_index

        while len(blocks) < total_blocks:
            index = self.search_for_block(samples, blocks, quality, index)

        return {**blocks, "index": index}

    def search_for_block(
        self,
        samples: List[int],
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

        bits = []
        length = length * 8 // lsb
        for i in range(content_start_index, content_start_index + length):
            extracted_bits = samples[i] & ((1 << lsb) - 1)
            bits.append(format(extracted_bits, f"0{lsb}b"))

        bits_str = "".join(bits)

        data_bytes = bytearray()
        for i in range(0, len(bits_str), 8):
            byte = bits_str[i : i + 8]
            data_bytes.append(int(byte, 2))

        try:
            if self.block_names[len(blocks)] == "HMAC":
                blocks[self.block_names[len(blocks)]] = bytes(data_bytes)
            else:
                blocks[self.block_names[len(blocks)]] = data_bytes.decode(
                    "utf-8", errors="ignore"
                )
        except Exception as e:
            print(f"Error decoding block: {e}")

        return content_start_index + length

    def magic_str_index(self, quality: str) -> int:
        lsb = self.qualities[quality]
        return len(self.MAGIC_STRING) * 8 // lsb

    def extract_header_blocks_from_header_bytes(self, header: bytes):
        blocks = {}
        current_index = 0

        if header.startswith(self.MAGIC_STRING):
            blocks["MAGIC_STRING"] = self.MAGIC_STRING.decode()  
            current_index = len(self.MAGIC_STRING)
        else:
            raise ValueError("Invalid header: MAGIC_STRING 'CIPHERNEST' not found")

        total_blocks = len(self.full_block_names)
        block_idx = 1

        while block_idx < total_blocks:
            delimiter_index = header.find(self.block_delimiter, current_index)

            if delimiter_index == -1:
                raise ValueError(f"Delimiter '{self.block_delimiter.decode()}' not found")

            length_str = header[current_index:delimiter_index].decode()  
            try:
                length = int(length_str)
            except ValueError:
                raise ValueError(f"Invalid length '{length_str}' for block '{self.full_block_names[block_idx]}'")

            current_index = delimiter_index + len(self.block_delimiter)

            data = header[current_index:current_index + length]

            try:
                if self.full_block_names[block_idx] == "HMAC":
                    blocks[self.full_block_names[block_idx]] = bytes(data)
                else:
                    blocks[self.full_block_names[block_idx]] = data.decode(
                        "utf-8", errors="ignore"
                    )
            except Exception as e:
                print(f"Error decoding block: {e}")

            current_index += length
            block_idx += 1


        return blocks
