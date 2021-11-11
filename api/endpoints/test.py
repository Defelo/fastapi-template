from typing import Any

from fastapi import APIRouter

from ..auth import user_auth
from ..exceptions import responses
from ..exceptions.auth import user_responses
from ..schemas.test import TestResponse

router = APIRouter(tags=["test"])


@router.get("/test", responses=responses(TestResponse))
async def test() -> Any:
    return {"result": "hello world"}


@router.get("/auth", dependencies=[user_auth], responses=user_responses(list[int]))
async def test_auth() -> Any:
    return [1, 2, 3]
