from pydantic import BaseModel

from ..utils import example


class TestResponse(BaseModel):
    result: str

    Config = example(result="hello world")
