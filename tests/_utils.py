import importlib
import inspect
import runpy
import sys
from contextlib import asynccontextmanager
from functools import partial
from types import ModuleType
from typing import AsyncContextManager, AsyncIterator, Callable, TypeVar, cast
from unittest.mock import MagicMock


T = TypeVar("T")


def mock_list(size: int) -> list[MagicMock]:
    return [MagicMock() for _ in range(size)]


def mock_dict(size: int, string_keys: bool = False) -> dict[MagicMock | str, MagicMock]:
    return {(str(MagicMock()) if string_keys else MagicMock()): MagicMock() for _ in range(size)}


def reload_module(module: ModuleType) -> ModuleType:
    return importlib.reload(module)


def import_module(name: str | ModuleType) -> ModuleType:
    if isinstance(name, ModuleType):
        return import_module(name.__name__)

    old_module = sys.modules.pop(name, None)
    new_module = importlib.import_module(name)
    if old_module:
        sys.modules[name] = old_module
    return new_module


def run_module(module: ModuleType) -> None:
    runpy.run_path(inspect.getfile(module), {}, "__main__")


def mock_call_assertions(n: int) -> tuple[list[Callable[[], None]], Callable[[], None]]:
    events: list[int] = []

    def assert_calls() -> None:
        assert events == [*range(n)]

    callbacks = [cast(Callable[[], None], partial(events.append, i)) for i in range(n)]

    return callbacks, assert_calls


def mock_asynccontextmanager(
    n: int, value: T
) -> tuple[Callable[[], AsyncContextManager[T]], list[Callable[[], None]], Callable[[], None]]:
    [enter_callback, *callbacks, exit_callback], assert_calls = mock_call_assertions(n + 2)

    async def context_manager() -> AsyncIterator[T]:
        enter_callback()
        yield value
        exit_callback()

    return asynccontextmanager(context_manager), callbacks, assert_calls
