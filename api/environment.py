import os
import re
import secrets
from collections import namedtuple
from os import getenv
from typing import Optional

import jq


def get_bool(key: str, default: bool) -> bool:
    """Get a boolean from an environment variable."""

    return getenv(key, str(default)).lower() in ("true", "t", "yes", "y", "1")


LOG_LEVEL: str = getenv("LOG_LEVEL", "INFO")

HOST = getenv("HOST", "0.0.0.0")  # noqa: S104
PORT = int(getenv("PORT", "8000"))
ROOT_PATH: str = getenv("ROOT_PATH", "")

DEBUG: bool = get_bool("DEBUG", False)
RELOAD: bool = get_bool("RELOAD", False)

JWT_SECRET = getenv("JWT_SECRET", secrets.token_urlsafe(64))
ACCESS_TOKEN_TTL = int(getenv("ACCESS_TOKEN_TTL", "300"))  # 5 minutes
REFRESH_TOKEN_TTL = int(getenv("REFRESH_TOKEN_TTL", "2592000"))  # 30 days
OAUTH_REGISTER_TOKEN_TTL = int(getenv("OAUTH_REGISTER_TOKEN_TTL", "600"))  # 10 minutes
HASH_TIME_COST = int(getenv("HASH_TIME_COST", "2"))
HASH_MEMORY_COST = int(getenv("HASH_MEMORY_COST", "102400"))
MFA_VALID_WINDOW: int = int(getenv("MFA_VALID_WINDOW", "1"))

ADMIN_USERNAME = getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = getenv("ADMIN_PASSWORD", "admin")

OPEN_REGISTRATION: bool = get_bool("OPEN_REGISTRATION", False)
OPEN_OAUTH_REGISTRATION: bool = get_bool("OPEN_OAUTH_REGISTRATION", False)

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

OAuthProvider = namedtuple(
    "OAuthProvider",
    [
        "name",
        "client_id",
        "client_secret",
        "authorize_url",
        "token_url",
        "userinfo_url",
        "userinfo_headers",
        "user_id_path",
        "display_name_path",
    ],
)
OAUTH_PROVIDERS: dict[str, OAuthProvider] = {}
for var in os.environ:
    if not (match := re.match(r"^OAUTH_([A-Z0-9_]+)_CLIENT_ID$", var)):
        continue

    provider_id = match.group(1)
    provider_name = getenv(f"OAUTH_{provider_id}_NAME", provider_id)
    client_id = getenv(f"OAUTH_{provider_id}_CLIENT_ID")
    client_secret = getenv(f"OAUTH_{provider_id}_CLIENT_SECRET")
    authorize_url = getenv(f"OAUTH_{provider_id}_AUTHORIZE_URL")
    token_url = getenv(f"OAUTH_{provider_id}_TOKEN_URL")
    userinfo_url = getenv(f"OAUTH_{provider_id}_USERINFO_URL")
    userinfo_headers = getenv(f"OAUTH_{provider_id}_USERINFO_HEADERS", "Authorization=Bearer%20{access_token}")
    user_id_path = getenv(f"OAUTH_{provider_id}_USERINFO_ID_PATH")
    display_name_path = getenv(f"OAUTH_{provider_id}_USERINFO_NAME_PATH", "null")

    if not all([client_id, client_secret, authorize_url, token_url, userinfo_url, user_id_path]):
        continue

    OAUTH_PROVIDERS[provider_id.lower()] = OAuthProvider(
        provider_name,
        client_id,
        client_secret,
        authorize_url,
        token_url,
        userinfo_url,
        userinfo_headers,
        jq.compile(user_id_path),
        jq.compile(display_name_path),
    )
