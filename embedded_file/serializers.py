from rest_framework import serializers


class EmbeddedFileUploadSerializer(serializers.Serializer):
    embedded_file = serializers.FileField()
    password = serializers.CharField(required=False, default=None)

    def validate_embedded_file(self, value):
        valid_extensions = ["wav", "mp3", "flac"]
        extension = value.name.split(".")[-1].lower()

        if extension not in valid_extensions:
            raise serializers.ValidationError(
                "Unsupported file extension for embedded file. Allowed types are: wav, mp3, flac."
            )

        return value
