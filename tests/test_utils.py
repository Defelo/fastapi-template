from unittest.mock import MagicMock

from pytest_mock import MockerFixture

from .utils import mock_dict, mock_list
from api import utils


async def test__run_in_thread() -> None:
    out = []
    res = MagicMock()
    args = tuple(mock_list(5))
    kwargs = mock_dict(5, True)

    @utils.run_in_thread
    def func(*_args: MagicMock, **_kwargs: MagicMock) -> MagicMock:
        out.append((_args, _kwargs))
        return res

    assert await func(*args, **kwargs) == res
    assert out == [(args, kwargs)]


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
    arg = MagicMock()
    arg.Config.schema_extra = {"example": (expected := MagicMock())}

    assert utils.get_example(arg) == expected


async def test__example(mocker: MockerFixture) -> None:
    get_example_patch = mocker.patch("api.utils.get_example")

    args = [a := MagicMock(), b := MagicMock()]
    get_example_patch.side_effect = lambda x: MagicMock(
        items=lambda: [(x.first.key, x.first.value), (x.second.key, x.second.value)]
    )
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
