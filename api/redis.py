from typing import Callable, cast

from aioredis import Redis, from_url

from .environment import REDIS_DB, REDIS_HOST, REDIS_PORT
from .logger import get_logger


logger = get_logger(__name__)

# global redis connection
logger.debug("initializing redis connection")
redis: Redis = cast(Callable[..., Redis], from_url)(
    f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}", encoding="utf-8", decode_responses=True
)
