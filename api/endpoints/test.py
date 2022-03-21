from typing import Any

from fastapi import APIRouter

from ..auth import auth
from ..exceptions.auth import InvalidTokenError
from ..schemas.test import TestResponse
from ..utils import responses

router = APIRouter(tags=["test"])


@router.get("/test", responses=responses(TestResponse))
async def test() -> Any:
    return {"result": "hello world"}


@router.get("/auth", dependencies=[auth], responses=responses(list[int], InvalidTokenError))
async def test_auth() -> Any:
    return [1, 2, 3]
