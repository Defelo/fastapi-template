from os import getenv
from typing import Optional


def get_bool(key: str, default: bool) -> bool:
    """Get a boolean from an environment variable."""

    return getenv(key, str(default)).lower() in ("true", "t", "yes", "y", "1")


LOG_LEVEL: str = getenv("LOG_LEVEL", "INFO")

HOST = getenv("HOST", "0.0.0.0")  # noqa: S104
PORT = int(getenv("PORT", "8000"))
ROOT_PATH: str = getenv("ROOT_PATH", "")

DEBUG: bool = get_bool("DEBUG", False)
RELOAD: bool = get_bool("RELOAD", False)

# database configuration
DB_DRIVER: str = getenv("DB_DRIVER", "mysql+aiomysql")
DB_HOST: str = getenv("DB_HOST", "localhost")
DB_PORT: int = int(getenv("DB_PORT", "3306"))
DB_DATABASE: str = getenv("DB_DATABASE", "fastapi")
DB_USERNAME: str = getenv("DB_USERNAME", "fastapi")
DB_PASSWORD: str = getenv("DB_PASSWORD", "fastapi")
POOL_RECYCLE: int = int(getenv("POOL_RECYCLE", 300))
POOL_SIZE: int = int(getenv("POOL_SIZE", 20))
MAX_OVERFLOW: int = int(getenv("MAX_OVERFLOW", 20))
SQL_SHOW_STATEMENTS: bool = get_bool("SQL_SHOW_STATEMENTS", False)

# redis configuration
REDIS_HOST = getenv("REDIS_HOST", "redis")
REDIS_PORT = int(getenv("REDIS_PORT", "6379"))
REDIS_DB = int(getenv("REDIS_DB", "0"))

SENTRY_DSN: Optional[str] = getenv("SENTRY_DSN")  # sentry data source name
