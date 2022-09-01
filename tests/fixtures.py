from typing import AsyncIterator
from unittest.mock import AsyncMock

import pytest
from _pytest.monkeypatch import MonkeyPatch
from httpx import AsyncClient
from pytest_mock import MockerFixture
from sqlalchemy.ext.asyncio import create_async_engine

from api.app import app
from api.database import db


@pytest.fixture(autouse=True)
async def database(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(db, "engine", create_async_engine("sqlite+aiosqlite:///:memory:"))
    await db.create_tables()


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


@pytest.fixture
async def auth_client(client: AsyncClient, mocker: MockerFixture) -> AsyncIterator[AsyncClient]:
    mocker.patch("api.auth.StaticTokenAuth._check_token", AsyncMock(return_value=True))
    mocker.patch("api.auth.JWTAuth.__call__", AsyncMock(return_value={"foo": "bar"}))
    yield client
