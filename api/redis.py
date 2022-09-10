from typing import Callable, cast

from aioredis import Redis, from_url

from .logger import get_logger
from .settings import settings


logger = get_logger(__name__)

# global redis connection
logger.debug("initializing redis connection")
redis: Redis = cast(Callable[..., Redis], from_url)(settings.redis_url, encoding="utf-8", decode_responses=True)
