from rest_framework import status
from rest_framework.test import APITestCase, APIClient
import io
from django.urls import reverse
from pydub import AudioSegment
from unittest.mock import patch
from utils.constants import Code
from utils.exceptions import RunOutOfFreeSpaceError

class EmbeddedFileTests(APITestCase):

    def setUp(self):
        self.client = APIClient()
        self.cover_upload_url = reverse('cover-upload')  
        self.embed_url = reverse('embed')  
        self.mock_audio_file = io.BytesIO()
        self.mock_audio_file.name = 'test.wav'

        audio = AudioSegment.silent(duration=1000)  
        audio.export(self.mock_audio_file, format="wav")
        self.mock_audio_file.seek(0)  

    @patch('lsb.lsb.LSBSteganography.get_free_space', return_value=1024)
    def test_cover_upload_success(self, mock_get_free_space):
        data = {
            'cover_file': self.mock_audio_file,
            'output_quality': 'very_low',
            'compressed': False,
        }
        response = self.client.post(self.cover_upload_url, data, format='multipart')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json().get('code'), Code.SUCCESS.value)

    @patch('lsb.lsb.LSBSteganography.get_free_space', return_value=-1)
    def test_cover_upload_run_out_of_free_space(self, mock_get_free_space):
        data = {
            'cover_file': self.mock_audio_file,
            'output_quality': "very_low",
            'compressed': False,
        }
        response = self.client.post(self.cover_upload_url, data, format='multipart')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json().get('code'), Code.RUN_OUT_OF_FREE_SPACE.value)
    
    @patch('lsb.lsb.LSBSteganography.embed')
    def test_embed_success(self, mock_embed):
        secret_file = io.BytesIO(b"This is secret data")
        secret_file.name = 'secret.txt'

        data = {
            'cover_file': self.mock_audio_file,
            'output_quality': "very_low",
            'compressed': False,
            'secret_files': [secret_file],
            'password': 'testpassword',
        }
        response = self.client.post(self.embed_url, data, format='multipart')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(f'attachment; filename="{self.mock_audio_file.name}"', response['Content-Disposition'])

    @patch('lsb.lsb.LSBSteganography.embed', side_effect=RunOutOfFreeSpaceError)
    def test_embed_run_out_of_free_space(self, mock_embed):
        secret_file = io.BytesIO(b"This is secret data")
        secret_file.name = 'secret.txt'

        data = {
            'cover_file': self.mock_audio_file,
            'output_quality': "very_low",
            'compressed': False,
            'secret_files': [secret_file],
            'password': 'testpassword',
        }
        response = self.client.post(self.embed_url, data, format='multipart')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json().get('code'), Code.RUN_OUT_OF_FREE_SPACE.value)
