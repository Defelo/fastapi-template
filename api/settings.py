import json
import secrets
from typing import Any, Literal

import jq
from jq import _Program
from pydantic import BaseModel, BaseSettings, Field, validator


class OAuthProvider(BaseModel):
    name: str
    client_id: str
    client_secret: str
    authorize_url: str
    token_url: str
    userinfo_url: str
    userinfo_headers: dict[str, str]
    userinfo_id_path: _Program
    userinfo_name_path: _Program

    @validator("userinfo_headers", pre=True)
    def _validate_userinfo_headers(cls, value: str) -> Any:  # noqa: N805
        return json.loads(value)

    @validator("userinfo_id_path", pre=True)
    def _validate_userinfo_id_path(cls, value: str) -> _Program:  # noqa: N805
        return jq.compile(value)

    @validator("userinfo_name_path", pre=True)
    def _validate_userinfo_name_path(cls, value: str) -> _Program:  # noqa: N805
        return jq.compile(value)

    class Config:
        arbitrary_types_allowed = True


class Settings(BaseSettings):
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    host: str = "0.0.0.0"  # noqa: S104
    port: int = 8000
    root_path: str = ""

    debug: bool = False
    reload: bool = False

    jwt_secret: str = secrets.token_urlsafe(64)

    internal_jwt_ttl: int = 10

    access_token_ttl: int = 300
    refresh_token_ttl: int = 2592000
    oauth_register_token_ttl: int = 600
    hash_time_cost: int = 2
    hash_memory_cost: int = 102400
    mfa_valid_window: int = 1
    login_fails_before_captcha: int = 3

    recaptcha_sitekey: str | None = None
    recaptcha_secret: str | None = None

    admin_username: str = "admin"
    admin_password: str = "admin"

    open_registration: bool = False
    open_oauth_registration: bool = False

    database_url: str = Field(
        "mysql+aiomysql://fastapi:fastapi@mariadb:3306/fastapi",
        regex=r"^(mysql\+aiomysql|postgresql\+asyncpg|sqlite\+aiosqlite)://.*$",
    )
    pool_recycle: int = 300
    pool_size: int = 20
    max_overflow: int = 20
    sql_show_statements: bool = False

    redis_url: str = Field("redis://redis:6379/0", regex=r"^redis://.*$")

    sentry_dsn: str | None = None

    oauth_providers: dict[str, OAuthProvider] = {}

    class Config:
        env_nested_delimiter = "__"


settings = Settings()
