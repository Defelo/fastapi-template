from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
from _pytest.monkeypatch import MonkeyPatch
from pytest_mock import MockerFixture

from api.services.internal import InternalService, InternalServiceError
from api.settings import settings


async def test__internal_service__get_token(mocker: MockerFixture, monkeypatch: MonkeyPatch) -> None:
    encode_jwt = mocker.patch("api.services.internal.encode_jwt")
    monkeypatch.setattr(settings, "internal_jwt_ttl", 123)
    service = MagicMock()
    service.name = "MY_SERVICE"

    result = InternalService._get_token(service)

    encode_jwt.assert_called_once_with({"aud": "my_service"}, timedelta(seconds=123))
    assert result == encode_jwt()


@pytest.mark.parametrize(
    "code,ok",
    [(200, True), (201, True), (401, False), (403, False), (404, True), (500, False), (501, False), (502, False)],
)
async def test__internal_service__handle_error(code: int, ok: bool) -> None:
    response = AsyncMock(status_code=code, text="response text asdf")

    if ok:
        await InternalService._handle_error(response)
        response.aread.assert_not_called()
    else:
        with pytest.raises(InternalServiceError) as e:
            await InternalService._handle_error(response)
        response.aread.assert_called_once_with()
        assert e.value.args == (response, "response text asdf")


async def test__internal_service__client(mocker: MockerFixture, monkeypatch: MonkeyPatch) -> None:
    async_client = mocker.patch("api.services.internal.AsyncClient")
    service = MagicMock(value="http://example.service:1234/test/")

    result = InternalService.client.fget(service)  # type: ignore

    async_client.assert_called_once()
    args = async_client.call_args[1]
    assert result == async_client()

    assert args["base_url"] == "http://example.service:1234/test/_internal"
    assert args["headers"] == {"Authorization": service._get_token()}

    event_hooks = args["event_hooks"]
    assert [*event_hooks] == ["response"]
    assert event_hooks["response"] == [service._handle_error]
