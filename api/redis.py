from asyncio import get_event_loop

import nest_asyncio
from aioredis import create_redis_pool, Redis

from environment import REDIS_HOST, REDIS_PORT, REDIS_DB
from logger import get_logger

logger = get_logger(__name__)

nest_asyncio.apply()

loop = get_event_loop()

# global redis connection
logger.debug("initializing redis connection")
redis: Redis = loop.run_until_complete(
    create_redis_pool(f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}", encoding="utf-8", loop=loop),
)
