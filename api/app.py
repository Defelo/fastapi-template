import asyncio
from typing import Callable, Awaitable, TypeVar

from fastapi import FastAPI, Request, HTTPException
from fastapi.exception_handlers import http_exception_handler
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .database import db, db_context
from .endpoints import test, user, session, oauth
from .environment import ROOT_PATH, DEBUG
from .logger import get_logger
from .models import User, Session
from .version import get_version

T = TypeVar("T")

logger = get_logger(__name__)

app = FastAPI(title="FastAPI", version=get_version().description, root_path=ROOT_PATH)

if DEBUG:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
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
            async with db_context():
                await Session.clean_expired_sessions()
        except Exception as e:
            logger.exception(e)
        await asyncio.sleep(20 * 60)


@app.on_event("startup")
async def on_startup() -> None:
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


app.include_router(user.router)
app.include_router(session.router)
app.include_router(oauth.router)
app.include_router(test.router)
