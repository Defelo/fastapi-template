from httpx import AsyncClient


async def test__test(client: AsyncClient) -> None:
    response = await client.get("/test")
    assert response.status_code == 200
    assert response.json() == {"result": "hello world"}


async def test__auth(client: AsyncClient) -> None:
    response = await client.get("/auth")
    assert response.status_code == 200
    assert response.json() == [1, 2, 3]
