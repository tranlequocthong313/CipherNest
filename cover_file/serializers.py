from rest_framework import serializers


class CoverUploadSerializer(serializers.Serializer):
    cover_file = serializers.FileField()
    output_quality = serializers.ChoiceField(
        choices=[("low", "LOW"), ("medium", "MEDIUM"), ("high", "HIGH")]
    )

    def validate_cover_file(self, value):
        # Kiểm tra phần mở rộng của tệp
        valid_extensions = ["wav", "mp3", "flac"]
        extension = value.name.split(".")[-1].lower()

        if extension not in valid_extensions:
            raise serializers.ValidationError(
                "Unsupported file extension. Allowed types are: wav, mp3, flac."
            )

        return value
