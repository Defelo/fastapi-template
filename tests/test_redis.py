from _pytest.monkeypatch import MonkeyPatch
from aioredis import Redis

from ._utils import import_module, reload_module
from api import environment, redis


async def test__redis(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("REDIS_DB", "42")
    monkeypatch.setenv("REDIS_PORT", "4953")
    monkeypatch.setenv("REDIS_HOST", "my_redis_host")
    reload_module(environment)

    r = import_module(redis).redis

    assert isinstance(r, Redis)
    assert r.connection_pool.connection_kwargs == {
        "host": "my_redis_host",
        "port": 4953,
        "db": 42,
        "encoding": "utf-8",
        "decode_responses": True,
    }
