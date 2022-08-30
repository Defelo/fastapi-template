"""Test endpoints (to be removed later)"""

from typing import Any

from fastapi import APIRouter

from ..auth import user_auth
from ..exceptions.auth import user_responses
from ..schemas.test import TestResponse
from ..utils.docs import responses


router = APIRouter(tags=["test"])


@router.get("/test", responses=responses(TestResponse))
async def test() -> Any:
    """Test endpoint."""

    return {"result": "hello world"}


@router.get("/auth", dependencies=[user_auth], responses=user_responses(list[int]))
async def test_auth() -> Any:
    """
    Test endpoint with authentication.

    *Requirements:* **USER**
    """

    return [1, 2, 3]
