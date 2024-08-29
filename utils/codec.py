import zlib


# Compression/Decompression
class CoDec:
    def compress_data(self, data: bytes) -> bytes:
        compressed_data = zlib.compress(data)
        return compressed_data

    def decompress_data(self, compressed_data: bytes) -> bytes:
        decompressed_data = zlib.decompress(compressed_data)
        return decompressed_data
