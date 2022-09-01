from typing import Any

from pydantic import BaseModel, Field

from ..utils.docs import example


class TestResponse(BaseModel):
    result: str = Field(description="Test result")

    Config = example(result="hello world")


class JWTAuthResponse(BaseModel):
    test: list[int]
    data: dict[Any, Any]

    Config = example(test=[1, 2, 3, 4, 5], data={"foo": "bar"})
