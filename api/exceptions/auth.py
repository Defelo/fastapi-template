from typing import Any, Type

from fastapi import status

from .api_exception import APIException
from ..utils.docs import responses


class InvalidTokenError(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Invalid token"
    description = "This access token is invalid or the session has expired."


def internal_responses(default: type, *args: Type[APIException]) -> dict[int | str, dict[str, Any]]:
    """api responses for admin_auth dependency"""

    return responses(default, *args, InvalidTokenError)
