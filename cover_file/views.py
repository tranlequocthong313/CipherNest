from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import CoverUploadSerializer
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile


class CoverUploadView(APIView):
    def post(self, request):
        serializer = CoverUploadSerializer(data=request.data)
        if serializer.is_valid():
            cover_file = serializer.validated_data["cover_file"]
            output_quality = serializer.validated_data["output_quality"]

            # Save the file to the server
            path = default_storage.save(
                f"uploads/covers/{cover_file.name}", ContentFile(cover_file.read())
            )

            # Process the file based on output_quality (this is just a placeholder)
            # You would typically handle the audio processing here.

            return Response(
                {
                    "message": "File uploaded successfully",
                    "output_quality": output_quality,
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
