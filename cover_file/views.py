from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from utils.constants import Code
from lsb.file import File
from .serializers import CoverUploadSerializer
from lsb.lsb import LSBSteganography
from pydub import AudioSegment
import io


class CoverUploadView(APIView):
    def __init__(self, **kwargs):
        self.algorithm = LSBSteganography()
        super().__init__(**kwargs)

    def post(self, request):
        serializer = CoverUploadSerializer(data=request.data)
        if serializer.is_valid():
            cover_file = serializer.validated_data["cover_file"]
            output_quality = serializer.validated_data["output_quality"]
            compressed = serializer.validated_data["compressed"] or False
            secret_files_data = serializer.validated_data.get("secret_files", [])

            file_bytes = cover_file.read()
            audio = AudioSegment.from_file(io.BytesIO(file_bytes), format="wav")

            try:
                samples = audio.get_array_of_samples()
                if header_blocks := self.algorithm.get_header_blocks(samples=samples):
                    sizes = File.arr_file_sizes(header_blocks["EMBEDDED_SIZES"])
                    filenames = File.arr_filenames(header_blocks["FILENAMES"])
                    version = header_blocks["VERSION"]
                    return Response(
                        {
                            "code": Code.IS_EMBEDDED_BY_SYSTEM.value,
                            "message": f"Your embedded file is on version {version} and includes {len(filenames)} secret file(s)",
                            "data": {
                                "filenames": filenames,
                                "sizes": sizes,
                                "version": version,
                            },
                        },
                        status=status.HTTP_200_OK,
                    )
                else:
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
                        quality=output_quality,
                        compressed=compressed,
                        passphrase=None,
                    )
                    if free_space >= 0:
                        return Response(
                            {
                                "code": Code.SUCCESS.value,
                                "message": f"Your free space is {free_space} Bytes",
                                "data": free_space,
                            },
                            status=status.HTTP_200_OK,
                        )
                    return Response(
                        {
                            "code": Code.RUN_OUT_OF_FREE_SPACE.value,
                            "message": "You run out of free space",
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            except ValueError as e:
                return Response(
                    {"message": str(e), "code": Code.NOT_EMBEDDED_BY_SYSTEM.value},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
