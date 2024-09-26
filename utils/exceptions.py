from rest_framework import status
from utils.constants import Code


class BaseCustomException(Exception):
    """Base class for custom exceptions."""

    code = Code.INTERNAL_SERVER_ERROR.value
    message = "Internal server error"
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    def __init__(self, message=None, code=None):
        if message:
            self.message = message
        if code:
            self.code = code
        super().__init__(self.message)


class RunOutOfFreeSpaceError(BaseCustomException):
    code = Code.RUN_OUT_OF_FREE_SPACE.value
    message = "You have run out of free space"
    status_code = status.HTTP_400_BAD_REQUEST


class NotEmbeddedBySystemError(BaseCustomException):
    code = Code.NOT_EMBEDDED_BY_SYSTEM.value
    message = "The file is not embedded by the system"
    status_code = status.HTTP_400_BAD_REQUEST


class RequirePasswordError(BaseCustomException):
    code = Code.REQUIRE_PASSWORD.value
    message = "Password is required to proceed."
    status_code = status.HTTP_400_BAD_REQUEST


class WrongPasswordError(BaseCustomException):
    code = Code.WRONG_PASSWORD.value
    message = "The provided password is incorrect."
    status_code = status.HTTP_400_BAD_REQUEST


class DataCorruptedError(BaseCustomException):
    code = Code.DATA_CORRUPTED.value
    message = "The data has been corrupted or modified."
    status_code = status.HTTP_400_BAD_REQUEST
