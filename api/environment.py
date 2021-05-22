from os import getenv


def get_bool(key: str, default: bool) -> bool:
    """Get a boolean from an environment variable."""

    return getenv(key, str(default)).lower() in ("true", "t", "yes", "y", "1")


LOG_LEVEL: str = getenv("LOG_LEVEL", "INFO")

HOST = getenv("HOST", "0.0.0.0")  # noqa: S104
PORT = int(getenv("PORT", "8000"))
RELOAD = get_bool("RELOAD", False)

REDIS_HOST = getenv("REDIS_HOST", "redis")
REDIS_PORT = int(getenv("REDIS_PORT", "6379"))
REDIS_DB = int(getenv("REDIS_DB", "0"))

SENTRY_DSN: str = getenv("SENTRY_DSN")  # sentry data source name
