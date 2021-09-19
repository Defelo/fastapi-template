from fastapi import status

from .api_exception import APIException


class InvalidCredentialsError(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Invalid credentials"
    description = "This user does not exist or the password is incorrect."


class SessionNotFoundError(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    detail = "Session not found"
    description = "This session does not exist."


class InvalidRefreshTokenError(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Invalid refresh token"
    description = "This refresh token is invalid or the session has expired."
