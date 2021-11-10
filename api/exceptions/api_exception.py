from typing import Type, Any, Union

from fastapi import HTTPException
from uvicorn.protocols.http.h11_impl import STATUS_PHRASES


class APIException(HTTPException):
    status_code: int
    detail: str
    description: str

    def __init__(self) -> None:
        super().__init__(self.status_code, self.detail)


def responses(default: type, *args: Type[APIException]) -> dict[Union[int, str], dict[str, Any]]:
    exceptions: dict[int, list[Type[APIException]]] = {}
    for exc in args:
        exceptions.setdefault(exc.status_code, []).append(exc)

    out: dict[Union[int, str], dict[str, Any]] = {}
    for code, excs in exceptions.items():
        examples = {}
        for i, exc in enumerate(excs):
            name = exc.__name__ if len(excs) == 1 else f"{exc.__name__} ({i + 1}/{len(excs)})"
            examples[name] = {"description": exc.description, "value": {"detail": exc.detail}}

        out[code] = {
            "description": STATUS_PHRASES[code],
            "content": {"application/json": {"examples": examples}},
        }

    return out | {200: {"model": default}}
