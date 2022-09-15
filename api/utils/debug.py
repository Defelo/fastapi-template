import json
from typing import Awaitable, Callable, Type

import pydantic
from fastapi import Request
from fastapi.responses import StreamingResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel
from starlette.concurrency import iterate_in_threadpool

from api.logger import get_logger


logger = get_logger(__name__)


def _check_response_schema(method: str, route: APIRoute, status_code: int, body: bytes) -> None:
    if status_code in [405, 422]:
        return
    if not route.include_in_schema:
        return
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

    chunks = [chunk async for chunk in response.body_iterator]
    body = b"".join(chunks)

    response.body_iterator = iterate_in_threadpool(iter(chunks))

    if route := request.scope.get("route"):
        _check_response_schema(request.method, route, response.status_code, body)

    return response
