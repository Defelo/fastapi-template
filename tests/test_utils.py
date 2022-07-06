from unittest import IsolatedAsyncioTestCase
from unittest.mock import MagicMock, patch

from utils import mock_dict

from api import utils


class TestUtils(IsolatedAsyncioTestCase):
    async def test__responses(self) -> None:
        default = MagicMock()

        def make_exception(status_code: int) -> MagicMock:
            out = MagicMock()
            out.__name__ = MagicMock()
            out.status_code = status_code
            return out

        args = [a := make_exception(401), b := make_exception(403), c := make_exception(403), d := make_exception(404)]

        # noinspection PyTypeChecker
        result = utils.responses(default, *args)

        self.assertEqual(
            {
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
            },
            result,
        )

    async def test__get_example(self) -> None:
        arg = MagicMock()
        arg.Config.schema_extra = {"example": (expected := MagicMock())}

        result = utils.get_example(arg)  # noqa

        self.assertEqual(expected, result)

    @patch("api.utils.get_example")
    async def test__example(self, get_example_patch: MagicMock) -> None:
        args = [a := MagicMock(), b := MagicMock()]
        get_example_patch.side_effect = lambda x: MagicMock(
            items=lambda: [(x.first.key, x.first.value), (x.second.key, x.second.value)]
        )
        kwargs = mock_dict(5, True)

        result = utils.example(*args, **kwargs)

        # noinspection PyUnresolvedReferences
        self.assertEqual(
            {
                "example": {
                    a.first.key: a.first.value,
                    a.second.key: a.second.value,
                    b.first.key: b.first.value,
                    b.second.key: b.second.value,
                    **kwargs,
                }
            },
            result.schema_extra,
        )
