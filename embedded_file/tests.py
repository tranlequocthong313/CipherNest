import datetime
import json
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from unittest.mock import patch, MagicMock
import io
from pydub import AudioSegment

from utils.constants import Code
from utils.exceptions import RequirePasswordError, WrongPasswordError

class EmbeddedUploadViewTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse('embedded-upload')  
        self.mock_audio_file = io.BytesIO(b"dummy audio file content")  
        self.mock_audio_file.name = 'test_audio.wav'
    
    @patch('embedded_file.views.LSBSteganography.extract_data')
    @patch('embedded_file.views.Zip.create_zip')
    @patch('pydub.AudioSegment.from_file')
    def test_upload_embedded_file_success(self, mock_from_file, mock_create_zip, mock_extract_data):
        mock_audio = MagicMock(spec=AudioSegment)
        mock_audio.get_array_of_samples.return_value = [10] * 2000 
        mock_from_file.return_value = mock_audio

        mock_extract_data.return_value = {
            "metadata": {"FILENAMES": ["test_file.txt"], "EMBEDDED_SIZES": [1024]},
            "extracted_files": [("test_file.txt", b"some extracted content")]
        }

        mock_create_zip.return_value = io.BytesIO(b"dummy zip content")

        extracted_date = datetime.datetime.now().strftime("%Y%m%d")
        zip_filename = f"extracted_files_{extracted_date}.zip"

        data = {
            'embedded_file': self.mock_audio_file,
            'password': 'secret_password'
        }

        response = self.client.post(self.url, data, format='multipart')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/zip')
        self.assertTrue('Content-Disposition' in response)
        self.assertIn('attachment; filename=%s' % zip_filename, response['Content-Disposition'])

    @patch('embedded_file.views.LSBSteganography.extract_data')
    @patch('pydub.AudioSegment.from_file')
    def test_upload_file_without_password(self, mock_extract_data, mock_from_file):
        mock_audio = MagicMock(spec=AudioSegment)
        mock_audio.get_array_of_samples.return_value = [10] * 2000 
        mock_from_file.return_value = mock_audio

        mock_extract_data.side_effect = RequirePasswordError()

        data = {
            'embedded_file': self.mock_audio_file,
        }

        response = self.client.post(self.url, data, format='multipart')

        self.assertEqual(response.status_code, 400)  
        self.assertDictEqual({
            'code' : Code.REQUIRE_PASSWORD.value,
            'message' : "Password is required to proceed."
        }, json.loads(response.content.decode()))

    @patch('embedded_file.views.LSBSteganography.extract_data')
    @patch('pydub.AudioSegment.from_file')
    def test_upload_file_with_invalid_password(self, mock_extract_data, mock_from_file):
        mock_audio = MagicMock(spec=AudioSegment)
        mock_audio.get_array_of_samples.return_value = [10] * 2000 
        mock_from_file.return_value = mock_audio

        mock_extract_data.side_effect = WrongPasswordError()

        data = {
            'embedded_file': self.mock_audio_file,
            'password': 'secret_password'
        }

        response = self.client.post(self.url, data, format='multipart')

        self.assertEqual(response.status_code, 400)  
        self.assertDictEqual({
            'code': Code.WRONG_PASSWORD.value,
            'message' : "The provided password is incorrect."
        }, json.loads(response.content.decode()))

