from typing import Any, Type, cast

from pydantic import BaseConfig, BaseModel
from uvicorn.protocols.http.h11_impl import STATUS_PHRASES

from ..exceptions.api_exception import APIException


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
    return cast(dict[str, dict[str, Any]], arg.Config.schema_extra)["example"]


def example(*args: Type[BaseModel], **kwargs: Any) -> Type[BaseConfig]:
    ex = dict(e for arg in args for e in get_example(arg).items())
    return cast(Type[BaseConfig], type("Config", (BaseConfig,), {"schema_extra": {"example": ex | kwargs}}))


def add_endpoint_links_to_openapi_docs(openapi_schema: dict[str, Any]) -> None:
    anchors: dict[str, str] = {
        f"{method.upper()} {name}": f"docs#/{route['tags'][0]}/{route['operationId']}"
        for name, path in openapi_schema["paths"].items()
        for method, route in path.items()
    }

    def replace(text: str) -> str:
        for endpoint, anchor in anchors.items():
            text = text.replace(f"`{endpoint}`", f"[`{endpoint}`]({anchor})")
        return text

    def add_links(schema: Any) -> Any:
        if isinstance(schema, dict):
            for k, v in schema.items():
                schema[k] = add_links(v)
        elif isinstance(schema, list):
            for i, v in enumerate(schema):
                schema[i] = add_links(v)
        elif isinstance(schema, str):
            schema = replace(schema)
        return schema

    add_links(openapi_schema)
