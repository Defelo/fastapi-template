from os import getenv

HOST = getenv("HOST", "0.0.0.0")  # noqa: S104
PORT = int(getenv("PORT", "8000"))

REDIS_HOST = getenv("REDIS_HOST", "redis")
REDIS_PORT = int(getenv("REDIS_PORT", "6379"))
REDIS_DB = int(getenv("REDIS_DB", "0"))
