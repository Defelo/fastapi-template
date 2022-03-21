from typing import Any, cast, Type

from pydantic import BaseModel, BaseConfig
from uvicorn.protocols.http.h11_impl import STATUS_PHRASES

from .exceptions.api_exception import APIException


def responses(default: type, *args: Type[APIException]) -> dict[int | str, dict[str, Any]]:
    exceptions: dict[int, list[Type[APIException]]] = {}
    for exc in args:
        exceptions.setdefault(exc.status_code, []).append(exc)

    out: dict[int | str, dict[str, Any]] = {}
    for code, excs in exceptions.items():
        examples = {}
        for i, exc in enumerate(excs):
            name = exc.__name__ if len(excs) == 1 else f"{exc.__name__} ({i + 1}/{len(excs)})"
            examples[name] = {"description": exc.description, "value": {"detail": exc.detail}}

        out[code] = {"description": STATUS_PHRASES[code], "content": {"application/json": {"examples": examples}}}

    return out | {200: {"model": default}}


def get_example(arg: Type[BaseModel]) -> dict[str, Any]:
    # noinspection PyUnresolvedReferences
    return cast(dict[str, dict[str, Any]], arg.Config.schema_extra)["example"]


def example(*args: Type[BaseModel], **kwargs: Any) -> Type[BaseConfig]:
    ex = dict(e for arg in args for e in get_example(arg).items())
    return cast(Type[BaseConfig], type("Config", (BaseConfig,), {"schema_extra": {"example": ex | kwargs}}))
