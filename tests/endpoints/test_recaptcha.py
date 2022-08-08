from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient
from pytest_mock import MockerFixture


@pytest.mark.parametrize("sitekey", [None, "the_sitekey"])
async def test__get_recpatcha_sitekey(sitekey: str, client: AsyncClient, mocker: MockerFixture) -> None:
    mocker.patch("api.endpoints.recaptcha.recaptcha_enabled", MagicMock(return_value=bool(sitekey)))
    mocker.patch("api.endpoints.recaptcha.RECAPTCHA_SITEKEY", sitekey)

    response = await client.get("/recaptcha")
    assert response.status_code == 200
    assert response.json() == sitekey
