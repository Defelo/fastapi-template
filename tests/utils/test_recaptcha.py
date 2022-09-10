from contextlib import asynccontextmanager
from typing import Any, AsyncIterator
from unittest.mock import AsyncMock, MagicMock

import pytest
from _pytest.monkeypatch import MonkeyPatch
from pytest_mock import MockerFixture

from .._utils import mock_asynccontextmanager
from api.settings import settings
from api.utils import recaptcha


@pytest.mark.parametrize(
    "secret,sitekey,expected",
    [("", "", False), (None, None, False), ("foo", "", False), ("", "bar", False), ("foo", "bar", True)],
)
async def test__recaptcha_enabled(
    secret: str | None, sitekey: str | None, expected: bool, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "recaptcha_sitekey", sitekey)
    monkeypatch.setattr(settings, "recaptcha_secret", secret)

    assert recaptcha.recaptcha_enabled() == expected


async def test__check_recaptcha(mocker: MockerFixture, monkeypatch: MonkeyPatch) -> None:
    client_patch = mocker.patch("aiohttp.ClientSession")

    secret = MagicMock()
    token = MagicMock()
    expected = MagicMock()

    session = MagicMock()
    response = AsyncMock()

    client_patch.side_effect, func_callbacks, assert_calls = mock_asynccontextmanager(3, session)

    @asynccontextmanager
    async def session_context(url: str, data: dict[str, Any]) -> AsyncIterator[AsyncMock]:
        assert url == "https://www.google.com/recaptcha/api/siteverify"
        assert data == {"secret": secret, "response": token}

        func_callbacks[0]()
        yield response
        func_callbacks[2]()

    session.post.side_effect = session_context
    response.json.side_effect = lambda: func_callbacks[1]() or {"success": expected}

    monkeypatch.setattr(settings, "recaptcha_secret", secret)
    assert await recaptcha.check_recaptcha(token) == expected

    assert_calls()
    client_patch.assert_called_once()
    session.post.assert_called_once()
    response.json.assert_called_once()
