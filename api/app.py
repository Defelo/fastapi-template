"""
## Authentication
- To authenticate requests, the `Authorization` header must contain a valid API token.

## Requirements
Some endpoints require one or more of the following conditions to be met:
- **AUTH**: The request is authenticated using a valid API token.
"""

from typing import Any, Awaitable, Callable, TypeVar

from fastapi import FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .database import db, db_context
from .endpoints import ROUTERS
from .environment import DEBUG, ROOT_PATH, SENTRY_DSN
from .logger import get_logger, setup_sentry
from .utils.debug import check_responses
from .utils.docs import add_endpoint_links_to_openapi_docs
from .version import get_version


T = TypeVar("T")

logger = get_logger(__name__)

tags: list[Any] = []
app = FastAPI(
    title="FastAPI",
    description=__doc__,
    version=get_version().description,
    root_path=ROOT_PATH,
    root_path_in_servers=False,
    servers=[{"url": ROOT_PATH}] if ROOT_PATH else None,
    openapi_tags=tags,
)
for name, (router, description) in ROUTERS.items():
    app.include_router(router)
    tags.append({"name": name, "description": description})

if DEBUG:
    app.middleware("http")(check_responses)


def setup_app() -> None:
    add_endpoint_links_to_openapi_docs(app.openapi())

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


@app.on_event("startup")
async def on_startup() -> None:
    setup_app()


@app.on_event("shutdown")
async def on_shutdown() -> None:
    pass


@app.head("/status", include_in_schema=False)
async def status() -> None:
    pass
