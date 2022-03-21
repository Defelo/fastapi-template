import importlib
import runpy
import sys
from typing import Any, cast
from unittest import IsolatedAsyncioTestCase
from unittest.mock import MagicMock

from fastapi import APIRouter
from fastapi.routing import APIRoute

from api.endpoints import ROUTERS


class EndpointsTestCase(IsolatedAsyncioTestCase):
    ROUTER: APIRouter

    @classmethod
    def setUpClass(cls) -> None:
        assert cls.ROUTER in ROUTERS, "Router is not registered!"

    def get_route(self, method: str, path: str) -> APIRoute:
        routes = [
            route
            for route in cast(list[APIRoute], self.ROUTER.routes)
            if method in route.methods and route.path == path
        ]
        self.failIf(not routes, f"Route {method} {path} not found!")
        self.failIf(len(routes) > 1, f"There is more than one {method} {path} route!")
        return routes[0]


class AsyncMock(MagicMock):
    async def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return super(AsyncMock, self).__call__(*args, **kwargs)


def mock_list(size: int) -> list[MagicMock]:
    return [MagicMock() for _ in range(size)]


def mock_dict(size: int, string_keys: bool = False) -> dict[MagicMock | str, MagicMock]:
    return {(str(MagicMock()) if string_keys else MagicMock()): MagicMock() for _ in range(size)}


def import_module(name: str) -> Any:
    if module := sys.modules.get(name):
        return importlib.reload(module)

    return __import__(name)


def run_module(module: str) -> None:
    runpy.run_module(module, {}, "__main__")
