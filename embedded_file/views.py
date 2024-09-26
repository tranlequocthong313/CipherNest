from django.http import HttpResponse 
from rest_framework.views import APIView
import datetime
from rest_framework.views import APIView

from utils.format import file_extension
from utils.zip import Zip
from .serializers import EmbeddedFileUploadSerializer
from lsb.lsb import LSBSteganography
from pydub import AudioSegment
import io


class EmbeddedUploadView(APIView):
    def __init__(self, **kwargs):
        self.algorithm = LSBSteganography()
        self.zip = Zip()
        super().__init__(**kwargs)

    def post(self, request):
        serializer = EmbeddedFileUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        embedded_file = serializer.validated_data["embedded_file"]
        password = serializer.validated_data.get("password")

        file_bytes = embedded_file.read()
        audio = AudioSegment.from_file(io.BytesIO(file_bytes), format=file_extension(embedded_file))

        samples = audio.get_array_of_samples()

        data = self.algorithm.extract_data(samples=samples, passphrase=password)

        zip_buffer = self.zip.create_zip(response_data=data, password=password)
        extracted_date = datetime.datetime.now().strftime("%Y%m%d")
        zip_filename = f"extracted_files_{extracted_date}.zip"

        resp = HttpResponse(zip_buffer, content_type='application/zip')
        resp['Content-Disposition'] = 'attachment; filename=%s' % zip_filename
        return resp

