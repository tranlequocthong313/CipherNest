from typing import Any
from rest_framework import status
from rest_framework.serializers import ValidationError
from rest_framework.views import exception_handler
from rest_framework.response import Response

from cover_file.exceptions import BaseCustomException
from utils.constants import Code


def custom_exception_handler(exc: Any, context: Any = None):
    response = exception_handler(exc, context)

    if isinstance(exc, BaseCustomException) or issubclass(
        type(exc), BaseCustomException
    ):
        return Response(
            {
                "code": exc.code,
                "message": exc.message,
            },
            status=exc.status_code,
        )

    if isinstance(exc, ValidationError):
        return Response(
            {
                "code": Code.INVALID_REQUEST_DATA.value,
                "message": "Invalid request data",
                "errors": exc.detail,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    return response


def standard_response(code: int, message: str, data=None, status=200):
    response = {
        "code": code,
        "message": message,
    }
    if data:
        response["data"] = data

    return Response(response, status=status)
