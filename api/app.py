from typing import Awaitable, Callable, TypeVar

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from .database import db, db_context
from .endpoints import ROUTERS
from .environment import DEBUG, ROOT_PATH, SENTRY_DSN
from .logger import get_logger, setup_sentry
from .version import get_version


T = TypeVar("T")

logger = get_logger(__name__)

app = FastAPI(title="FastAPI", version=get_version().description, root_path=ROOT_PATH)
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


@app.on_event("startup")
async def on_startup() -> None:
    setup_app()

    await db.create_tables()


@app.on_event("shutdown")
async def on_shutdown() -> None:
    pass


@app.head("/status", tags=["status"])
async def status() -> None:
    pass
