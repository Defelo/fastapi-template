from httpx import AsyncClient


async def test__test(auth_client: AsyncClient) -> None:
    response = await auth_client.get("/_internal/test")
    assert response.status_code == 200
    assert response.json() == "ok"
