from typing import Any, AsyncIterator
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from pytest_mock import MockerFixture

from .utils import import_module
from api.app import app


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


@pytest.fixture
async def auth_client(client: AsyncClient, mocker: MockerFixture) -> AsyncIterator[AsyncClient]:
    mocker.patch("api.auth.HTTPAuth._check_token", AsyncMock(return_value=True))
    yield client


@pytest.fixture(autouse=True)
async def reload_modules_after_mock(request: Any, mocker: MockerFixture) -> AsyncIterator[None]:
    yield

    if marker := request.node.get_closest_marker("reload_modules"):
        mocker.stopall()
        for module in marker.args:
            import_module(module)
