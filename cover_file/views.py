from django.http import HttpResponse
from rest_framework.views import APIView
from rest_framework import status

from cover_file.exceptions import (
    RunOutOfFreeSpaceError,
)
from utils.constants import Algorithm, Code
from lsb.file import File
from utils.format import file_extension
from utils.response import standard_response
from .serializers import CoverUploadSerializer, EmbedSerializer
from lsb.lsb import LSBSteganography
from pydub import AudioSegment
import io


class CoverUploadView(APIView):
    def __init__(self, **kwargs):
        self.algorithm = LSBSteganography()
        super().__init__(**kwargs)

    def post(self, request):
        serializer = CoverUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        cover_file = serializer.validated_data["cover_file"]
        output_quality = serializer.validated_data["output_quality"]
        compressed = serializer.validated_data["compressed"] or False
        secret_files_data = serializer.validated_data.get("secret_files", [])
        password = serializer.validated_data.get("password")

        file_bytes = cover_file.read()
        audio = AudioSegment.from_file(io.BytesIO(file_bytes), format=file_extension(cover_file))

        samples = audio.get_array_of_samples()

        if header_blocks := self.algorithm.get_header_blocks(
            samples=samples, passphrase=password
        ):
            sizes = File.arr_file_sizes(header_blocks["EMBEDDED_SIZES"])
            filenames = File.arr_filenames(header_blocks["FILENAMES"])
            version = header_blocks["VERSION"]
            return standard_response(
                code=Code.IS_EMBEDDED_BY_SYSTEM.value,
                message=f"Your embedded file is on version {version} and includes {len(filenames)} secret file(s)",
                data={
                    "filenames": filenames,
                    "sizes": sizes,
                    "version": version,
                },
                status=status.HTTP_200_OK,
            )

        secret_files = []
        for secret_file in secret_files_data:
            secret_file_bytes = secret_file.read()
            secret_files.append(
                File(
                    name=secret_file.name,
                    size=secret_file.size,
                    data=secret_file_bytes,
                )
            )

        free_space = self.algorithm.get_free_space(
            samples=samples,
            secret_files=secret_files,
            quality=output_quality,
            compressed=compressed,
            passphrase=password,
        )
        if free_space >= 0:
            return standard_response(
                code=Code.SUCCESS.value,
                message=f"Your free space is {free_space} Bytes",
                data=free_space,
            )
        else:
            raise RunOutOfFreeSpaceError()


class EmbedView(APIView):
    def __init__(self, **kwargs):
        self.algorithm = LSBSteganography()
        super().__init__(**kwargs)

    def post(self, request):
        serializer = EmbedSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        cover_file = serializer.validated_data["cover_file"]
        output_quality = serializer.validated_data["output_quality"]
        compressed = serializer.validated_data["compressed"] or False
        algorithm = serializer.validated_data["algorithm"] or Algorithm.LSB
        secret_files_data = serializer.validated_data.get("secret_files", [])
        password = serializer.validated_data.get("password")

        file_bytes = cover_file.read()
        audio = AudioSegment.from_file(io.BytesIO(file_bytes), format=file_extension(cover_file))

        samples = audio.get_array_of_samples()

        secret_files = []
        for secret_file in secret_files_data:
            secret_file_bytes = secret_file.read()
            secret_files.append(
                File(
                    name=secret_file.name,
                    size=secret_file.size,
                    data=secret_file_bytes,
                )
            )

        self.algorithm.embed(
            samples=samples,  
            secret_files=secret_files,
            quality=output_quality,
            compressed=compressed,
            passphrase=password,
        )

        embedded_audio = audio._spawn(samples.tobytes())

        buffer = io.BytesIO()
        embedded_audio.export(buffer, format=file_extension(cover_file))
        buffer.seek(0)  

        resp = HttpResponse(buffer, content_type='audio/wav')
        resp['Content-Disposition'] = f'attachment; filename="{cover_file.name}"'

        return resp
