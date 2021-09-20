from fastapi import status

from api.exceptions.api_exception import APIException


class UserNotFoundError(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    detail = "User not found"
    description = "This user does not exist."


class UserAlreadyExistsError(APIException):
    status_code = status.HTTP_409_CONFLICT
    detail = "User already exists"
    description = "This user already exists."


class MFAAlreadyEnabledError(APIException):
    status_code = status.HTTP_409_CONFLICT
    detail = "MFA already enabled"
    description = "MFA is already enabled."


class MFANotInitializedError(APIException):
    status_code = status.HTTP_412_PRECONDITION_FAILED
    detail = "MFA not initialized"
    description = "MFA has not been initialized."


class InvalidCodeError(APIException):
    status_code = status.HTTP_412_PRECONDITION_FAILED
    detail = "Invalid code"
    description = "This mfa code is invalid or has expired."


class MFANotEnabledError(APIException):
    status_code = status.HTTP_412_PRECONDITION_FAILED
    detail = "MFA not enabled"
    description = "MFA is not enabled."
