from unittest.mock import MagicMock

from fastapi import FastAPI
from pydantic import BaseModel, Field
from pytest_mock import MockerFixture

from .._utils import mock_dict
from api.utils import docs


async def test__responses() -> None:
    default = MagicMock()

    def make_exception(status_code: int) -> MagicMock:
        out = MagicMock()
        out.__name__ = MagicMock()
        out.status_code = status_code
        return out

    args = [a := make_exception(401), b := make_exception(403), c := make_exception(403), d := make_exception(404)]

    result = docs.responses(default, *args)

    assert result == {
        200: {"model": default},
        401: {
            "description": b"Unauthorized",
            "content": {
                "application/json": {
                    "examples": {a.__name__: {"description": a.description, "value": {"detail": a.detail}}}
                }
            },
        },
        403: {
            "description": b"Forbidden",
            "content": {
                "application/json": {
                    "examples": {
                        f"{b.__name__} (1/2)": {"description": b.description, "value": {"detail": b.detail}},
                        f"{c.__name__} (2/2)": {"description": c.description, "value": {"detail": c.detail}},
                    }
                }
            },
        },
        404: {
            "description": b"Not Found",
            "content": {
                "application/json": {
                    "examples": {d.__name__: {"description": d.description, "value": {"detail": d.detail}}}
                }
            },
        },
    }


async def test__get_example() -> None:
    arg = MagicMock()
    arg.Config.schema_extra = {"example": (expected := MagicMock())}

    assert docs.get_example(arg) == expected


async def test__example(mocker: MockerFixture) -> None:
    get_example_patch = mocker.patch("api.utils.docs.get_example")

    args = [a := MagicMock(), b := MagicMock()]
    get_example_patch.side_effect = lambda x: MagicMock(
        items=lambda: [(x.first.key, x.first.value), (x.second.key, x.second.value)]
    )
    kwargs = mock_dict(5, True)

    result = docs.example(*args, **kwargs)

    assert result.schema_extra == {
        "example": {
            a.first.key: a.first.value,
            a.second.key: a.second.value,
            b.first.key: b.first.value,
            b.second.key: b.second.value,
            **kwargs,
        }
    }


async def test__add_endpoint_links_to_openapi_docs() -> None:
    app = FastAPI(
        description="`GET /test` test `POST /foobar`",
        openapi_tags=[{"name": "test", "description": "asdf `GET /test`"}],
    )

    class Model(BaseModel):
        test: str = Field(description="xyz `POST /foobar`")

    @app.get("/test", tags=["test"], responses=docs.responses(Model))
    async def test() -> None:
        """Test endpoint. `POST /foobar`"""
        pass

    @app.post("/foobar", tags=["test"])
    async def foobar() -> None:
        """Foobar endpoint. `GET /test`"""
        pass

    docs.add_endpoint_links_to_openapi_docs(app.openapi())
    schema = app.openapi()
    assert (
        schema["info"]["description"]
        == "[`GET /test`](docs#/test/test_test_get) test [`POST /foobar`](docs#/test/foobar_foobar_post)"
    )
    assert schema["tags"][0]["description"] == "asdf [`GET /test`](docs#/test/test_test_get)"
    assert (
        schema["paths"]["/test"]["get"]["description"]
        == "Test endpoint. [`POST /foobar`](docs#/test/foobar_foobar_post)"
    )
    assert (
        schema["paths"]["/foobar"]["post"]["description"] == "Foobar endpoint. [`GET /test`](docs#/test/test_test_get)"
    )
    assert (
        schema["components"]["schemas"]["Model"]["properties"]["test"]["description"]
        == "xyz [`POST /foobar`](docs#/test/foobar_foobar_post)"
    )
