from _pytest.monkeypatch import MonkeyPatch
from aioredis import Redis

from ._utils import import_module
from api import redis
from api.settings import settings


async def test__redis(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "redis_url", "redis://my_redis_host:4953/42")

    r = import_module(redis).redis

    assert isinstance(r, Redis)
    assert r.connection_pool.connection_kwargs == {
        "host": "my_redis_host",
        "port": 4953,
        "db": 42,
        "encoding": "utf-8",
        "decode_responses": True,
    }
