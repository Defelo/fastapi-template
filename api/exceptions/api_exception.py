from fastapi import HTTPException


class APIException(HTTPException):
    status_code: int
    detail: str
    description: str

    def __init__(self) -> None:
        super().__init__(self.status_code, self.detail)
