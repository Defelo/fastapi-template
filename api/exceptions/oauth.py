from fastapi import status

from .api_exception import APIException


class ProviderNotFoundError(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    detail = "Provider not found"
    description = "OAuth provider could not be found."


class InvalidOAuthCodeError(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Invalid code"
    description = "Invalid OAuth authorization code."


class InvalidOAuthTokenError(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Invalid OAuth token"
    description = "Invalid OAuth register token."


class RemoteAlreadyLinkedError(APIException):
    status_code = status.HTTP_409_CONFLICT
    detail = "Remote already linked"
    description = "The remote user has already been linked to another account."


class ConnectionNotFoundError(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    detail = "Connection not found"
    description = "This OAuth connection does not exist."
