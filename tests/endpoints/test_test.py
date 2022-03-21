from api.auth import auth
from api.endpoints.test import router
from utils import EndpointsTestCase


class TestTest(EndpointsTestCase):
    ROUTER = router

    async def test__test(self) -> None:
        route = self.get_route("GET", "/test")
        response = await route.endpoint()
        self.assertEqual({"result": "hello world"}, response)

    async def test__auth(self) -> None:
        route = self.get_route("GET", "/auth")
        self.assertEqual([auth], route.dependencies)
        response = await route.endpoint()
        self.assertEqual([1, 2, 3], response)
