from django.test import TestCase
from unittest.mock import patch
from django.test import TestCase

from lsb.lsb import LSBSteganography
from .file import File  
from .header import LsbHeader  
from .models import ExtractedPayload  
from utils.exceptions import NotEmbeddedBySystemError, DataCorruptedError, RequirePasswordError, RunOutOfFreeSpaceError, WrongPasswordError

class FileTests(TestCase):

    def setUp(self):
        self.test_data = b"Test data for file operations."
        self.file = File(name="test_file.txt", size=len(self.test_data), data=self.test_data)

    @patch('utils.codec.CoDec.compress_data')
    def test_compressed_data_and_size(self, mock_compress):
        mock_compress.return_value = b"compressed_data"
        compressed_data = self.file.compressed_data
        compressed_size = self.file.compressed_size
        self.assertEqual(compressed_data, b"compressed_data")
        mock_compress.assert_called_once_with(self.test_data)
        self.assertEqual(compressed_size, len(b"compressed_data"))

    def test_filenames(self):
        file1 = File(name="file1.txt", size=123, data=b"data1")
        file2 = File(name="file2.txt", size=456, data=b"data2")
        result = File.filenames_with_delimiter([file1, file2], delimiter='/')
        self.assertEqual(result, "file1.txt/file2.txt")

    def test_file_sizes(self):
        file1 = File(name="file1.txt", size=123, data=b"data1")
        file2 = File(name="file2.txt", size=456, data=b"data2")
        result = File.file_sizes_with_delimiter([file1, file2], delimiter='#')
        self.assertEqual(result, "123#456")

    @patch('utils.codec.CoDec.decompress_data')
    @patch('utils.endec.EnDec.decrypt_data')
    def test_decompress_decrypt(self, mock_decrypt, mock_decompress):
        mock_decrypt.return_value = self.test_data
        mock_decompress.return_value = self.test_data
        encrypted_data = b"encrypted_data"
        decrypted_data = File.decompress_decrypt("passphrase", encrypted_data)
        self.assertEqual(decrypted_data, self.test_data)
        mock_decrypt.assert_called_once_with("passphrase", encrypted_data)
        mock_decompress.assert_called_once_with(self.test_data)

    @patch('utils.endec.EnDec.encrypt_data')
    def test_encrypt(self, mock_encrypt):
        mock_encrypt.return_value = b"encrypted_data"
        encrypted_data = self.file.encrypt("passphrase")
        self.assertEqual(encrypted_data, b"encrypted_data")
        mock_encrypt.assert_called_once_with("passphrase", self.test_data)

    @patch('utils.endec.EnDec.encrypt_data')
    @patch('utils.codec.CoDec.compress_data')
    def test_compress_encrypt(self, mock_compress, mock_encrypt):
        mock_compress.return_value = b"compressed_data"
        mock_encrypt.return_value = b"encrypted_data"
        encrypted_data = self.file.compress_encrypt("passphrase")
        self.assertEqual(encrypted_data, b"encrypted_data")
        mock_compress.assert_called_once_with(self.test_data)
        mock_encrypt.assert_called_once_with("passphrase", b"compressed_data")

    def test_estimate_embedded_size(self):
        estimated_size = self.file.estimate_embedded_size(num_bits=2)
        self.assertIsInstance(estimated_size, int)

    def test_total_size(self):
        file1 = File(name="file1.txt", size=123, data=b"data1")
        file2 = File(name="file2.txt", size=456, data=b"data2")
        total = File.total_size([file1, file2])
        self.assertEqual(total, 579)


class LsbHeaderTestCase(TestCase):
    def setUp(self):
        self.magic_string = "CipherNest"
        self.version = "1.0"
        self.qualities = {'very_low': 8, "low": 4, "medium": 2, "high": 1}
        self.block_delimiter = 'BLK'
        self.secret_key = "secret_key"
        self.header = LsbHeader(self.magic_string, self.version, self.qualities, self.block_delimiter, self.secret_key)
        self.secret_files = [
            File(name="test.txt", size=len(b"test data"), data=b"test data"),
            File(name="test2.pdf", size=len(b"test data 2"), data=b"test data 2"),
            File(name="test3.png", size=len(b"test data 3"), data=b"test data 3"),
        ]
        self.props = self.header.Props(secret_files=self.secret_files, passphrase="mypassword", quality='very_low', compressed=True)

    def test_length(self):
        header_length = self.header.length(self.props)
        self.assertIsInstance(header_length, int)

    def test_make_header(self):
        header_data = self.header.make_header(self.props)
        blocks = self.header.extract_header_blocks_from_header_bytes(header_data)
        self.assertIsInstance(header_data, bytes)
        self.assertIn("FILENAMES", blocks)
        self.assertIn("HMAC", blocks)
        self.assertIn("CF", blocks)
        self.assertIn("EF", blocks)
        self.assertIn("VERSION", blocks)
        self.assertIn("VERSION", blocks)
        self.assertIn("FILENAMES", blocks)
        self.assertIn("EMBEDDED_SIZES", blocks)
        self.assertIn("HMAC", blocks)
        self.assertIn("MAGIC_STRING", blocks)

    def test_verify_hmac_valid(self):
        header_data = self.header.make_header(self.props)
        blocks = self.header.extract_header_blocks_from_header_bytes(header_data)
        self.assertTrue(self.header.verify_hmac("mypassword", blocks))

    def test_verify_hmac_invalid(self):
        header_data = self.header.make_header(self.props)
        blocks = self.header.extract_header_blocks_from_header_bytes(header_data)
        self.assertFalse(self.header.verify_hmac("wrongpassword", blocks))
#
    def test_get_quality_from_embedded_data_exception(self):
        samples = [67, 105, 112, -152, -155, 114, -178, 101, -141, -140]
        quality = self.header.get_quality_from_embedded_data(samples)
        self.assertIn(quality, self.qualities)

    def test_get_quality_from_embedded_data_invalid(self):
        samples = [-181, 49, 75, 49, -205, 66, 76, 75, 49, 46, -208, 50, -200, 66,]
        with self.assertRaises(NotEmbeddedBySystemError):
            self.header.get_quality_from_embedded_data(samples, raise_exception=True)
        quality = self.header.get_quality_from_embedded_data(samples, raise_exception=False)
        self.assertIsNone(quality)

    def test_magic_str_index(self):
        index = self.header.magic_str_index("medium")
        self.assertIsInstance(index, int)
        self.assertEqual(index, len(self.magic_string)*8 // self.qualities['medium'])

    def test_extract_header_blocks(self):
        samples = [67, 105, 112, 104, 101, 114, 78, 101, 115, 116, -207, 66, 76, -181, -207, 49, 66, -180, 75, 49, 51, -190, -180, 75, 49, -210, -208, 50, 56, -190, 76, 75, -140, -155, 115, 116, 46, 116, 120, 116, 47, -140, 101, 115, -140, 50, 46, -144, -156, 102, 47, -140, -155, 115, 116, -205, -210, 112, 110, -153, -200, 66, 76, -181, -202, 52, -209, -202, 52, 47, -202, -204, 51, 50, -190, 76, 75, -202, 179, 237, 119, -184, -63, 118, 54, -235, -168, 168, 104, 8, -28, -25, 26, 77, 199, -101, -168, 243, 187, -140, -150, 229, 243, 247, -224, 241, 78, 241, 46]        
        quality = 'very_low'
        start_index = self.header.magic_str_index(quality)
        blocks = self.header.extract_header_blocks(samples=samples, quality=quality, start_index=start_index)
        self.assertIn("FILENAMES", blocks)
        self.assertIn("HMAC", blocks)
        self.assertIn("CF", blocks)
        self.assertIn("EF", blocks)
        self.assertIn("VERSION", blocks)
        self.assertIn("VERSION", blocks)
        self.assertIn("FILENAMES", blocks)
        self.assertIn("EMBEDDED_SIZES", blocks)
        self.assertIn("HMAC", blocks)
        self.assertTrue(self.header.verify_hmac("mypassword", blocks))




class ExtractedPayloadTestCase(TestCase):
    def setUp(self):
        self.metadata = {
            "EF": "1",
            "CF": "1",
            "VERSION": "1.0",
            "FILENAMES": ["file1.txt", "file2.pdf"],
            "EMBEDDED_SIZES": [100, 200],
            "HMAC": "abcd1234"
        }
        self.extracted_files = [("file1.txt", b"file1_content"), ("file2.pdf", b"file2_content")]
        self.payload = ExtractedPayload(metadata=self.metadata, extracted_files=self.extracted_files)

    def test_is_encrypted(self):
        self.assertTrue(self.payload.is_encrypted())
        payload_no_encryption = ExtractedPayload(metadata={"EF": "0"}, extracted_files=[])
        self.assertFalse(payload_no_encryption.is_encrypted())

    def test_is_compressed(self):
        self.assertTrue(self.payload.is_compressed())
        payload_no_compression = ExtractedPayload(metadata={"CF": "0"}, extracted_files=[])
        self.assertFalse(payload_no_compression.is_compressed())

    def test_get_version(self):
        self.assertEqual(self.payload.get_version(), "1.0")
        payload_no_version = ExtractedPayload(metadata={}, extracted_files=[])
        self.assertEqual(payload_no_version.get_version(), None)

    def test_get_filenames(self):
        self.assertEqual(self.payload.get_filenames(), ["file1.txt", "file2.pdf"])
        payload_no_filenames = ExtractedPayload(metadata={}, extracted_files=[])
        self.assertEqual(payload_no_filenames.get_filenames(), [])

    def test_get_embedded_sizes(self):
        self.assertEqual(self.payload.get_embedded_sizes(), [100, 200])
        payload_no_sizes = ExtractedPayload(metadata={}, extracted_files=[])
        self.assertEqual(payload_no_sizes.get_embedded_sizes(), [])

    def test_get_hmac(self):
        self.assertEqual(self.payload.get_hmac(), "abcd1234")
        payload_no_hmac = ExtractedPayload(metadata={}, extracted_files=[])
        self.assertEqual(payload_no_hmac.get_hmac(), None)


class LSBSteganographyTestCase(TestCase):
    def setUp(self):
        self.stego = LSBSteganography()
        self.samples = [10] * 2000  
        self.secret_files = [  
            File(name="test.txt", size=len(b"test data"), data=b"test data"),
            File(name="test2.pdf", size=len(b"test data 2"), data=b"test data 2"),
            File(name="test3.png", size=len(b"test data 3"), data=b"test data 3")
        ]
    
    def test_get_free_space(self):
        free_space = self.stego.get_free_space(
            samples=self.samples,
            secret_files=self.secret_files,
            quality="medium",
            compressed=True,
            passphrase="mypassword"
        )
        self.assertGreater(free_space, 0)  
    
    def test_invalid_quality_raises_error(self):
        with self.assertRaises(ValueError):
            self.stego.get_free_space(self.samples, self.secret_files, quality="invalid_quality")

    def test_run_out_of_free_space(self):
        small_samples = [10] * 10  
        with self.assertRaises(RunOutOfFreeSpaceError):
            self.stego.embed(small_samples, self.secret_files, quality="medium")

    def test_embed_and_extract(self):
        self.stego.embed(
            samples=self.samples,
            secret_files=self.secret_files,
            quality="medium",
            compressed=False,
            passphrase=None
        )
        extracted_payload = self.stego.extract_data(self.samples)
        self.assertIsInstance(extracted_payload, ExtractedPayload)

    def test_encryption_requires_password(self):
        samples_encrypted = [0b00000000] * 1000  
        with patch.object(LsbHeader, 'get_quality_from_embedded_data', return_value="medium"):
            with patch.object(LsbHeader, 'extract_header_blocks', return_value={"EF": "1", "HMAC": "valid_hmac"}):
                with self.assertRaises(RequirePasswordError):
                    self.stego.extract_data(samples_encrypted, passphrase=None)

    def test_wrong_password_error(self):
        samples_encrypted = [0b00000000] * 1000  # Simulating encrypted samples
        with patch.object(LsbHeader, 'get_quality_from_embedded_data', return_value="medium"):
            with patch.object(LsbHeader, 'extract_header_blocks', return_value={"EF": "1", "HMAC": b"valid_hmac"}):
                with self.assertRaises(WrongPasswordError):
                    self.stego.extract_data(samples_encrypted, passphrase="wrong_passphrase")

    def test_data_corrupted_error(self):
        corrupted_samples = [0b00000000] * 1000  
        with patch.object(LsbHeader, 'get_quality_from_embedded_data', return_value="medium"):
            with patch.object(LsbHeader, 'verify_hmac', return_value=False):
                with self.assertRaises(DataCorruptedError):
                    self.stego.extract_data(corrupted_samples)

    def test_multithread_embedding(self):
        result_index = self.stego.embed_data_singlethread(
            samples=self.samples,
            secret_files=self.secret_files,
            lsb=2,
            start_index=0
        )
        self.assertGreater(result_index, 0)  
