"""
## Authentication
- To authenticate requests, the `Authorization` header must contain a valid access token (JWT which contains the user's
ID and the session ID).
- The access token can be obtained by logging in to an exising account (see `POST /sessions` and `POST /sessions/oauth`)
or by creating an account (see `POST /users`). This access token is only valid for a short period of time
(usually 5 minutes).
- If the access token is expired, a new access token can be obtained by using the refresh token (see `PUT /session`)
which is also returned when creating a session. This will also invalidate the refresh token and generate a new one.
- If the refresh token is not used to refresh the session within a configured period of time (usually 30 days) the
session expires and the user must log in again on this device.

## Special parameters
- In addition to the usual user ids the `user_id` path parameter used in most endpoints also accepts the special values
`me` and `self` which refer to the currently authenticated user.

## Requirements
Some endpoints require one or more of the following conditions to be met:
- **USER**: The user is authenticated and has a valid session.
- **SELF**: The authenticated user must be the same as the affected user. Requires **USER**.
- **ADMIN**: The authenticated user must be an admin. Requires **USER**.
"""


import asyncio
from typing import Awaitable, Callable, TypeVar

from fastapi import FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .database import db, db_context
from .endpoints import ROUTERS
from .environment import DEBUG, ROOT_PATH, SENTRY_DSN
from .logger import get_logger, setup_sentry
from .models import User
from .models.session import clean_expired_sessions
from .version import get_version


T = TypeVar("T")

logger = get_logger(__name__)

app = FastAPI(title="FastAPI", description=__doc__, version=get_version().description, root_path=ROOT_PATH)
for router in ROUTERS:
    app.include_router(router)


def setup_app() -> None:
    if SENTRY_DSN:
        logger.debug("initializing sentry")
        setup_sentry(app, SENTRY_DSN, "FastAPI", get_version().description)

    if DEBUG:
        app.add_middleware(
            CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
        )


@app.middleware("http")
async def db_session(request: Request, call_next: Callable[..., Awaitable[T]]) -> T:
    async with db_context():
        return await call_next(request)


@app.exception_handler(StarletteHTTPException)
async def rollback_on_exception(request: Request, exc: HTTPException) -> JSONResponse:
    await db.session.rollback()
    return await http_exception_handler(request, exc)


async def clean_expired_sessions_loop() -> None:
    while True:
        try:
            await clean_expired_sessions()
        except Exception as e:
            logger.exception(e)
        await asyncio.sleep(20 * 60)


@app.on_event("startup")
async def on_startup() -> None:
    setup_app()

    await db.create_tables()
    asyncio.create_task(clean_expired_sessions_loop())

    async with db_context():
        await User.initialize()


@app.on_event("shutdown")
async def on_shutdown() -> None:
    pass


@app.head("/status", tags=["status"])
async def status() -> None:
    pass
