from urllib.parse import urlsplit
from django.conf import settings
from rest_framework import serializers
from .domains import destination, short_name


class CreateSerializer(serializers.Serializer):
    original = serializers.CharField(required=True, trim_whitespace=False)
    shortened = serializers.CharField(required=False, allow_blank=True, trim_whitespace=False)

    def validate_original(self, value):
        try:
            return destination(value, settings.APPROVED_DOMAINS, [urlsplit(settings.SHORTENER_URL).hostname])
        except ValueError as error:
            raise serializers.ValidationError(str(error)) from error

    def validate_shortened(self, value):
        if not value:
            return value
        try:
            return short_name(value)
        except ValueError as error:
            raise serializers.ValidationError(str(error)) from error
