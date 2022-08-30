"""
## Authentication
- To authenticate requests, the `Authorization` header must contain a valid API token.

## Requirements
Some endpoints require one or more of the following conditions to be met:
- **AUTH**: The request is authenticated using a valid API token.
"""

import json
from typing import Any, Awaitable, Callable, Type, TypeVar

import pydantic
from fastapi import FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

from .database import db, db_context
from .endpoints import ROUTERS
from .environment import DEBUG, ROOT_PATH, SENTRY_DSN
from .logger import get_logger, setup_sentry
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


def _check_response_schema(method: str, route: APIRoute, status_code: int, body: bytes) -> None:
    if status_code not in route.responses:
        logger.error(f"[{method} {route.path}] no response schema defined for status code {status_code}")
        return

    response = route.responses[status_code]

    if "model" in response:
        response_schema: Type[BaseModel] = response["model"]
        try:
            pydantic.parse_raw_as(response_schema, body)
        except Exception as e:
            logger.error(f"[{method} {route.path}] response schema validation failed ({status_code}):\n{e}")
    elif not json.loads(body) in (
        v.get("value") for v in response.get("content", {}).get("application/json", {}).get("examples", {}).values()
    ):
        logger.error(f"[{method} {route.path}] response schema validation failed ({status_code})")


async def check_responses(
    request: Request, call_next: Callable[..., Awaitable[StreamingResponse]]
) -> StreamingResponse:
    response: StreamingResponse = await call_next(request)
    if response.headers.get("Content-type") != "application/json":
        return response

    body = b""
    async for chunk in response.body_iterator:
        body += chunk

    if route := request.scope.get("route"):
        _check_response_schema(request.method, route, response.status_code, body)

    return StreamingResponse(
        content=body, status_code=response.status_code, headers=dict(response.headers), media_type=response.media_type
    )


if DEBUG:
    app.middleware("http")(check_responses)


@app.exception_handler(StarletteHTTPException)
async def rollback_on_exception(request: Request, exc: HTTPException) -> JSONResponse:
    await db.session.rollback()
    return await http_exception_handler(request, exc)


@app.on_event("startup")
async def on_startup() -> None:
    setup_app()

    await db.create_tables()


@app.on_event("shutdown")
async def on_shutdown() -> None:
    pass


@app.head("/status", include_in_schema=False)
async def status() -> None:
    pass
