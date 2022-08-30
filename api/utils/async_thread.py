from asyncio import get_event_loop
from concurrent.futures import ThreadPoolExecutor
from functools import wraps
from typing import Any, Awaitable, Callable, TypeVar


T = TypeVar("T")

executor = ThreadPoolExecutor()


def run_in_thread(func: Callable[..., T]) -> Callable[..., Awaitable[T]]:
    @wraps(func)
    async def inner(*args: Any, **kwargs: Any) -> T:
        return await get_event_loop().run_in_executor(executor, lambda: func(*args, **kwargs))

    return inner
