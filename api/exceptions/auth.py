from typing import Any, Type

from fastapi import status

from .api_exception import APIException
from ..utils import responses


class InvalidTokenError(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Invalid token"
    description = "This access token is invalid or the session has expired."


class PermissionDeniedError(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    detail = "Permission denied"
    description = "The user is not allowed to use this endpoint."


def user_responses(default: type, *args: Type[APIException]) -> dict[int | str, dict[str, Any]]:
    """api responses for user_auth dependency"""

    return responses(default, *args, InvalidTokenError)


def admin_responses(default: type, *args: Type[APIException]) -> dict[int | str, dict[str, Any]]:
    """api responses for admin_auth dependency"""

    return user_responses(default, *args, PermissionDeniedError)
