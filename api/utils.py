from typing import Any, cast, Type

from pydantic import BaseModel, BaseConfig


def get_example(arg: Type[BaseModel]) -> dict[str, Any]:
    # noinspection PyUnresolvedReferences
    return cast(dict[str, dict[str, Any]], arg.Config.schema_extra)["example"]


def example(*args: Type[BaseModel], **kwargs: Any) -> Type[BaseConfig]:
    ex = dict(e for arg in args for e in get_example(arg).items())
    return cast(Type[BaseConfig], type("Config", (BaseConfig,), {"schema_extra": {"example": ex | kwargs}}))
