from unittest.mock import MagicMock

from .._utils import mock_dict, mock_list
from api.utils import async_thread


async def test__run_in_thread() -> None:
    out = []
    res = MagicMock()
    args = tuple(mock_list(5))
    kwargs = mock_dict(5, True)

    @async_thread.run_in_thread
    def func(*_args: MagicMock, **_kwargs: MagicMock) -> MagicMock:
        out.append((_args, _kwargs))
        return res

    assert await func(*args, **kwargs) == res
    assert out == [(args, kwargs)]
