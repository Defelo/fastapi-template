from typing import AsyncIterator

import pytest
from httpx import AsyncClient

from api.app import app


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    async with AsyncClient(app=app, base_url="http://test", headers={"Authorization": "secret token"}) as client:
        yield client
