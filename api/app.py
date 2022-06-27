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
from .models import Session, User
from .version import get_version


T = TypeVar("T")

logger = get_logger(__name__)

app = FastAPI(title="FastAPI", version=get_version().description, root_path=ROOT_PATH)


def setup_app() -> None:
    if SENTRY_DSN:
        logger.debug("initializing sentry")
        setup_sentry(app, SENTRY_DSN, "FastAPI", get_version().description)

    if DEBUG:
        app.add_middleware(
            CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
        )

    for router in ROUTERS:
        app.include_router(router)


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
            async with db_context():
                await Session.clean_expired_sessions()
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
