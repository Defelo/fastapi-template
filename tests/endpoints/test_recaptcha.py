from unittest.mock import MagicMock

import pytest
from _pytest.monkeypatch import MonkeyPatch
from httpx import AsyncClient
from pytest_mock import MockerFixture

from api.settings import settings


@pytest.mark.parametrize("sitekey", [None, "the_sitekey"])
async def test__get_recpatcha_sitekey(
    sitekey: str, client: AsyncClient, mocker: MockerFixture, monkeypatch: MonkeyPatch
) -> None:
    mocker.patch("api.endpoints.recaptcha.recaptcha_enabled", MagicMock(return_value=bool(sitekey)))
    monkeypatch.setattr(settings, "recaptcha_sitekey", sitekey)

    response = await client.get("/recaptcha")
    assert response.status_code == 200
    assert response.json() == sitekey
