from typing import Any, AsyncIterator
from unittest.mock import AsyncMock, MagicMock

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
async def session(request: Any) -> AsyncIterator[MagicMock]:
    session = MagicMock()
    session.user.enabled = True
    session.user.admin = False
    if marker := request.node.get_closest_marker("user_params"):
        for k, v in marker.kwargs.items():
            setattr(session.user, k, v)
            if k == "id":
                session.user_id = v
    yield session


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


@pytest.fixture
async def user_client(client: AsyncClient, session: MagicMock, mocker: MockerFixture) -> AsyncIterator[AsyncClient]:
    mocker.patch("api.auth.UserAuth._get_session", AsyncMock(return_value=session))
    yield client


@pytest.fixture
async def admin_client(user_client: AsyncClient, session: MagicMock) -> AsyncIterator[AsyncClient]:
    session.user.admin = True
    yield user_client
