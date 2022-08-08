from httpx import AsyncClient


async def test__test(client: AsyncClient) -> None:
    response = await client.get("/test")
    assert response.status_code == 200
    assert response.json() == {"result": "hello world"}


async def test__auth__unauthorized(client: AsyncClient) -> None:
    response = await client.get("/auth")
    assert response.status_code == 401


async def test__auth__authorized(auth_client: AsyncClient) -> None:
    response = await auth_client.get("/auth")
    assert response.status_code == 200
    assert response.json() == [1, 2, 3]
