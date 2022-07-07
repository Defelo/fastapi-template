from typing import Any
from unittest.mock import MagicMock, patch

from pytest_mock import MockerFixture

from .utils import mock_dict
from api import utils


async def test__responses() -> None:
    default = MagicMock()

    def make_exception(status_code: int) -> MagicMock:
        out = MagicMock()
        out.__name__ = MagicMock()
        out.status_code = status_code
        return out

    args = [a := make_exception(401), b := make_exception(403), c := make_exception(403), d := make_exception(404)]

    result = utils.responses(default, *args)

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
    arg: Any = MagicMock()
    arg.Config.schema_extra = {"example": (expected := MagicMock())}

    assert utils.get_example(arg) == expected


async def test__example(mocker: MockerFixture) -> None:
    get_example_patch = mocker.patch("api.utils.get_example")
    get_example_patch.side_effect = lambda x: MagicMock(
        items=lambda: [(x.first.key, x.first.value), (x.second.key, x.second.value)]
    )

    args = [a := MagicMock(), b := MagicMock()]
    kwargs = mock_dict(5, True)

    result = utils.example(*args, **kwargs)

    assert result.schema_extra == {
        "example": {
            a.first.key: a.first.value,
            a.second.key: a.second.value,
            b.first.key: b.first.value,
            b.second.key: b.second.value,
            **kwargs,
        }
    }
