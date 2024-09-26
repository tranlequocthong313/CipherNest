from rest_framework import serializers

from utils.constants import EXTENSIONS_OF_SUPPORTED_FILE_FORMATS, OUTPUT_QUALITY


class CoverUploadSerializer(serializers.Serializer):
    cover_file = serializers.FileField()
    compressed = serializers.BooleanField(required=False, default=False)
    output_quality = serializers.ChoiceField(choices=OUTPUT_QUALITY)
    password = serializers.CharField(required=False, default=None)
    secret_files = serializers.ListField(
        child=serializers.FileField(), required=False, allow_empty=True
    )

    def validate_cover_file(self, value):
        valid_extensions = EXTENSIONS_OF_SUPPORTED_FILE_FORMATS
        extension = value.name.split(".")[-1].lower()

        if extension not in valid_extensions:
            raise serializers.ValidationError(
                "Unsupported file extension for cover file. Allowed types are: wav, mp3, flac, aiff."
            )

        return value

class EmbedSerializer(CoverUploadSerializer):
    algorithm = serializers.CharField(required=False, default=None)
