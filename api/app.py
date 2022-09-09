"""
## Authentication
- To authenticate requests, the `Authorization` header must contain a valid API token.

## Requirements
Some endpoints require one or more of the following conditions to be met:
- **AUTH**: The request is authenticated using a valid API token (static/JWT).
"""

from typing import Awaitable, Callable, TypeVar

from fastapi import FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .database import db, db_context
from .endpoints import ROUTER, TAGS
from .logger import get_logger, setup_sentry
from .settings import settings
from .utils.debug import check_responses
from .utils.docs import add_endpoint_links_to_openapi_docs
from .version import get_version


T = TypeVar("T")

logger = get_logger(__name__)

app = FastAPI(
    title="FastAPI",
    description=__doc__,
    version=get_version().description,
    root_path=settings.root_path,
    root_path_in_servers=False,
    servers=[{"url": settings.root_path}] if settings.root_path else None,
    openapi_tags=TAGS,
)
app.include_router(ROUTER)

if settings.debug:
    app.middleware("http")(check_responses)


def setup_app() -> None:
    add_endpoint_links_to_openapi_docs(app.openapi())

    if settings.sentry_dsn:
        logger.debug("initializing sentry")
        setup_sentry(app, settings.sentry_dsn, "FastAPI", get_version().description)

    if settings.debug:
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


@app.on_event("startup")
async def on_startup() -> None:
    setup_app()


@app.on_event("shutdown")
async def on_shutdown() -> None:
    pass


@app.head("/status", include_in_schema=False)
async def status() -> None:
    pass
