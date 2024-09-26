import os
from io import BytesIO
from django.http import Http404
from django.test import TestCase
from utils.constants import Code
from utils.format import file_extension
from rest_framework.test import APITestCase
from rest_framework.exceptions import ValidationError
from rest_framework import status
from rest_framework.response import Response
from utils.exceptions import BaseCustomException
from utils.response import custom_exception_handler, standard_response 
from unittest.mock import patch, MagicMock
from lsb.models import ExtractedPayload
from utils.exceptions import RequirePasswordError
from utils.zip import Zip 
from utils.exceptions import (
    BaseCustomException,
    RunOutOfFreeSpaceError,
    NotEmbeddedBySystemError,
    RequirePasswordError,
    WrongPasswordError,
    DataCorruptedError,
)
from utils.endec import EnDec 

class FileExtensionTest(TestCase):
    def test_valid_extension(self):
        class MockFile:
            def __init__(self, name):
                self.name = name

        file1 = MockFile("example.wav")
        file2 = MockFile("photo.aiff")
        file3 = MockFile("document.flac")
        
        self.assertEqual(file_extension(file1), "wav")
        self.assertEqual(file_extension(file2), "aiff")
        self.assertEqual(file_extension(file3), "flac")

    def test_file_without_extension(self):
        class MockFile:
            def __init__(self, name):
                self.name = name

        file = MockFile("file_without_extension")
        self.assertEqual(file_extension(file), "")

    def test_hidden_file_with_extension(self):
        class MockFile:
            def __init__(self, name):
                self.name = name

        file = MockFile(".hidden_file.wav")
        self.assertEqual(file_extension(file), "wav")
    
    def test_empty_file_name(self):
        class MockFile:
            def __init__(self, name):
                self.name = name

        file = MockFile("")
        self.assertEqual(file_extension(file), "")


class CustomExceptionHandlerTests(APITestCase):
    def test_base_custom_exception(self):
        exc = BaseCustomException(code=1001, message="Custom error")

        response = custom_exception_handler(exc, None)

        self.assertIsInstance(response, Response)
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.data, {
            "code": exc.code,
            "message": exc.message,
        })

    def test_validation_error(self):
        exc = ValidationError({"field": ["This field is required."]})

        response = custom_exception_handler(exc, None)

        self.assertIsInstance(response, Response)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data, {
            "code": Code.INVALID_REQUEST_DATA.value,  
            "message": "Invalid request data",
            "errors": exc.detail,
        })

    def test_generic_exception(self):
        response = custom_exception_handler(Exception("Some error"), None)

        self.assertIsInstance(response, Response)
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)  
        self.assertEqual(response.data, {
            "code": Code.INTERNAL_SERVER_ERROR.value,
            "message": "Internal server error",
        })  

    def test_404_exception(self):
        response = custom_exception_handler(Http404(), None)

        self.assertIsInstance(response, Response)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)  


class StandardResponseTests(APITestCase):
    def test_standard_response_with_data(self):
        code = 200
        message = "Success"
        data = {"key": "value"}

        response = standard_response(code, message, data, status=200)

        self.assertIsInstance(response, Response)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {
            "code": code,
            "message": message,
            "data": data,
        })

    def test_standard_response_without_data(self):
        code = Code.INVALID_REQUEST_DATA.value
        message = "Invalid Request Data"

        response = standard_response(code, message, status=400)

        self.assertIsInstance(response, Response)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data, {
            "code": code,
            "message": message,
        })


class ZipUtilTestCase(TestCase):

    @patch('utils.zip.File')
    def test_create_zip_with_user_password_and_compression(self, mock_file):
        response_data = MagicMock(spec=ExtractedPayload)
        response_data.is_encrypted.return_value = True
        response_data.is_compressed.return_value = True
        response_data.extracted_files = [('file1.txt', b'file data 1')]

        mock_file.decompress_decrypt.return_value = b'file data 1'

        zip_util = Zip()
        result = zip_util.create_zip(response_data, password='userpassword')

        self.assertIsInstance(result, BytesIO)

        mock_file.decompress_decrypt.assert_called_once_with('userpassword', b'file data 1')

    @patch('utils.zip.File')
    def test_create_zip_with_user_password_no_password(self, mock_file):
        response_data = MagicMock(spec=ExtractedPayload)
        response_data.is_encrypted.return_value = True
        response_data.is_compressed.return_value = False
        response_data.extracted_files = [('file1.txt', b'file data 1')]

        zip_util = Zip()
        
        with self.assertRaises(RequirePasswordError):
            zip_util.create_zip(response_data)

    @patch('utils.zip.File')
    def test_create_zip_without_user_password_and_compression(self, mock_file):
        response_data = MagicMock(spec=ExtractedPayload)
        response_data.is_encrypted.return_value = False
        response_data.is_compressed.return_value = False
        response_data.extracted_files = [('file1.txt', b'file data 1')]

        zip_util = Zip()
        result = zip_util.create_zip(response_data)

        self.assertIsInstance(result, BytesIO)

    @patch('utils.zip.File')
    def test_create_zip_without_user_password_with_compression(self, mock_file):
        response_data = MagicMock(spec=ExtractedPayload)
        response_data.is_encrypted.return_value = False
        response_data.is_compressed.return_value = True
        response_data.extracted_files = [('file1.txt', b'file data 1')]

        mock_file.decompress.return_value = b'file data 1'

        zip_util = Zip()
        result = zip_util.create_zip(response_data)

        self.assertIsInstance(result, BytesIO)

        mock_file.decompress.assert_called_once_with(b'file data 1')


class CustomExceptionTests(TestCase):

    def test_base_custom_exception(self):
        with self.assertRaises(BaseCustomException) as context:
            raise BaseCustomException(message="Test message", code=100)

        self.assertEqual(context.exception.message, "Test message")
        self.assertEqual(context.exception.code, 100)
        self.assertEqual(context.exception.status_code, 500)

    def test_run_out_of_free_space_error(self):
        with self.assertRaises(RunOutOfFreeSpaceError) as context:
            raise RunOutOfFreeSpaceError()

        self.assertEqual(context.exception.message, "You have run out of free space")
        self.assertEqual(context.exception.code, Code.RUN_OUT_OF_FREE_SPACE.value)
        self.assertEqual(context.exception.status_code, 400)

    def test_not_embedded_by_system_error(self):
        with self.assertRaises(NotEmbeddedBySystemError) as context:
            raise NotEmbeddedBySystemError()

        self.assertEqual(context.exception.message, "The file is not embedded by the system")
        self.assertEqual(context.exception.code, Code.NOT_EMBEDDED_BY_SYSTEM.value)
        self.assertEqual(context.exception.status_code, 400)

    def test_require_password_error(self):
        with self.assertRaises(RequirePasswordError) as context:
            raise RequirePasswordError()

        self.assertEqual(context.exception.message, "Password is required to proceed.")
        self.assertEqual(context.exception.code, Code.REQUIRE_PASSWORD.value)
        self.assertEqual(context.exception.status_code, 400)

    def test_wrong_password_error(self):
        with self.assertRaises(WrongPasswordError) as context:
            raise WrongPasswordError()

        self.assertEqual(context.exception.message, "The provided password is incorrect.")
        self.assertEqual(context.exception.code, Code.WRONG_PASSWORD.value)
        self.assertEqual(context.exception.status_code, 400)

    def test_data_corrupted_error(self):
        with self.assertRaises(DataCorruptedError) as context:
            raise DataCorruptedError()

        self.assertEqual(context.exception.message, "The data has been corrupted or modified.")
        self.assertEqual(context.exception.code, Code.DATA_CORRUPTED.value)
        self.assertEqual(context.exception.status_code, 400)


class EnDecTests(TestCase):

    def setUp(self):
        self.encryption_util = EnDec()
        self.passphrase = "test_passphrase"
        self.data = b"Test data for encryption."

    def test_estimate_encrypted_size(self):
        estimated_size = self.encryption_util.estimate_encrypted_size(len(self.data))
        self.assertIsInstance(estimated_size, int)
        self.assertGreater(estimated_size, len(self.data))  

    def test_derive_key(self):
        salt = os.urandom(16)
        key = self.encryption_util.derive_key(self.passphrase, salt)
        self.assertEqual(len(key), 32)  
        self.assertIsInstance(key, bytes)

    def test_encrypt_decrypt_data(self):
        encrypted_data = self.encryption_util.encrypt_data(self.passphrase, self.data)
        self.assertIsInstance(encrypted_data, bytes)
        self.assertGreater(len(encrypted_data), len(self.data))  

        decrypted_data = self.encryption_util.decrypt_data(self.passphrase, encrypted_data)
        self.assertEqual(decrypted_data, self.data)  

    def test_decrypt_invalid_passphrase(self):
        encrypted_data = self.encryption_util.encrypt_data(self.passphrase, self.data)
        decrypted_data = self.encryption_util.decrypt_data("wrong_passphrase", encrypted_data)
        self.assertNotEqual(decrypted_data, self.data)

    def test_decrypt_invalid_data(self):
        with self.assertRaises(ValueError):  
            self.encryption_util.decrypt_data(self.passphrase, b"invalid_data")
