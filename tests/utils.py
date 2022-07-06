import importlib
import inspect
import runpy
import sys
from types import ModuleType
from typing import Any
from unittest.mock import MagicMock


class AsyncMock(MagicMock):
    async def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return super(AsyncMock, self).__call__(*args, **kwargs)


def mock_list(size: int) -> list[MagicMock]:
    return [MagicMock() for _ in range(size)]


def mock_dict(size: int, string_keys: bool = False) -> dict[MagicMock | str, MagicMock]:
    return {(str(MagicMock()) if string_keys else MagicMock()): MagicMock() for _ in range(size)}


def reload_module(module: ModuleType) -> ModuleType:
    return importlib.reload(module)


def import_module(name: str | ModuleType) -> ModuleType:
    if isinstance(name, ModuleType):
        return reload_module(name)
    if module := sys.modules.get(name):
        return importlib.reload(module)

    return importlib.import_module(name)


def run_module(module: ModuleType) -> None:
    runpy.run_path(inspect.getfile(module), {}, "__main__")
