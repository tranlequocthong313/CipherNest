from rest_framework import serializers

from utils.constants import EXTENSIONS_OF_SUPPORTED_FILE_FORMATS


class EmbeddedFileUploadSerializer(serializers.Serializer):
    embedded_file = serializers.FileField()
    password = serializers.CharField(required=False, default=None)

    def validate_embedded_file(self, value):
        valid_extensions = EXTENSIONS_OF_SUPPORTED_FILE_FORMATS
        extension = value.name.split(".")[-1].lower()

        if extension not in valid_extensions:
            raise serializers.ValidationError(
                "Unsupported file extension for embedded file. Allowed types are: wav, mp3, flac, aiff."
            )

        return value
