"""Test endpoints (to be removed later)"""

from typing import Any

from fastapi import APIRouter

from ..auth import auth
from ..exceptions.auth import InvalidTokenError
from ..schemas.test import TestResponse
from ..utils import responses


router = APIRouter(tags=["test"])


@router.get("/test", responses=responses(TestResponse))
async def test() -> Any:
    """Test endpoint."""

    return {"result": "hello world"}


@router.get("/auth", dependencies=[auth], responses=responses(list[int], InvalidTokenError))
async def test_auth() -> Any:
    """
    Test endpoint with authentication.

    *Requirements:* **AUTH**
    """

    return [1, 2, 3]
