from fastapi import status

from .api_exception import APIException


class InvalidTokenError(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Invalid token"
    description = "This access token is invalid or the session has expired."
