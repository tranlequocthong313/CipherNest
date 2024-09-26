import zlib

class CoDec:
    def compress_data(self, data: bytes) -> bytes:
        return zlib.compress(data)

    def decompress_data(self, compressed_data: bytes) -> bytes:
        return zlib.decompress(compressed_data)

