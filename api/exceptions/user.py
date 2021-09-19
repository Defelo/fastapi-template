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
