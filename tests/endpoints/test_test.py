from httpx import AsyncClient


async def test__test(client: AsyncClient) -> None:
    response = await client.get("/test")
    assert response.status_code == 200
    assert response.json() == {"result": "hello world"}


async def test__auth_static__unauthorized(client: AsyncClient) -> None:
    response = await client.get("/auth/static")
    assert response.status_code == 401


async def test__auth_static__authorized(auth_client: AsyncClient) -> None:
    response = await auth_client.get("/auth/static")
    assert response.status_code == 200
    assert response.json() == [1, 2, 3]


async def test__auth_jwt__unauthorized(client: AsyncClient) -> None:
    response = await client.get("/auth/jwt")
    assert response.status_code == 401


async def test__auth_jwt__authorized(auth_client: AsyncClient) -> None:
    response = await auth_client.get("/auth/jwt")
    assert response.status_code == 200
    assert response.json() == {"test": [1, 2, 3, 4, 5], "data": {"foo": "bar"}}


async def test__auth_user__unauthorized(client: AsyncClient) -> None:
    response = await client.get("/auth/user")
    assert response.status_code == 401


async def test__auth_user__authorized(user_client: AsyncClient) -> None:
    response = await user_client.get("/auth/user")
    assert response.status_code == 200
    assert response.json() == [2, 4, 6]
