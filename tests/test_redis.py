from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch

from aioredis import Redis
from utils import import_module


class TestRedis(IsolatedAsyncioTestCase):
    @patch("api.environment.REDIS_DB", 42)
    @patch("api.environment.REDIS_PORT", 4953)
    @patch("api.environment.REDIS_HOST", "my_redis_host")
    async def test__redis(self) -> None:
        redis = import_module("api.redis").redis.redis

        self.assertIsInstance(redis, Redis)
        self.assertEqual(
            {"host": "my_redis_host", "port": 4953, "db": 42, "encoding": "utf-8", "decode_responses": True},
            redis.connection_pool.connection_kwargs,
        )
