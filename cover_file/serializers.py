from rest_framework import serializers


class CoverUploadSerializer(serializers.Serializer):
    cover_file = serializers.FileField()
    compressed = serializers.BooleanField(required=False, default=False)
    output_quality = serializers.ChoiceField(
        choices=[
            ("very_low", "VERY_LOW"),
            ("low", "LOW"),
            ("medium", "MEDIUM"),
            ("high", "HIGH"),
        ]
    )
    password = serializers.CharField(required=False, default=None)
    secret_files = serializers.ListField(
        child=serializers.FileField(), required=False, allow_empty=True
    )

    def validate_cover_file(self, value):
        valid_extensions = ["wav", "mp3", "flac"]
        extension = value.name.split(".")[-1].lower()

        if extension not in valid_extensions:
            raise serializers.ValidationError(
                "Unsupported file extension for cover file. Allowed types are: wav, mp3, flac."
            )

        return value
