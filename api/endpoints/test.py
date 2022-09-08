"""Test endpoints (to be removed later)"""

from typing import Any

from fastapi import APIRouter

from ..auth import jwt_auth, static_token_auth, user_auth
from ..exceptions.auth import InvalidTokenError, user_responses
from ..schemas.test import JWTAuthResponse, TestResponse
from ..utils.docs import responses


router = APIRouter()


@router.get("/test", responses=responses(TestResponse))
async def test() -> Any:
    """Test endpoint."""

    return {"result": "hello world"}


@router.get("/auth/static", dependencies=[static_token_auth], responses=responses(list[int], InvalidTokenError))
async def test_auth_static() -> Any:
    """
    Test endpoint with authentication.

    *Requirements:* **AUTH**
    """

    return [1, 2, 3]


@router.get("/auth/jwt", responses=responses(JWTAuthResponse, InvalidTokenError))
async def test_auth_jwt(data: dict[Any, Any] = jwt_auth) -> Any:
    """
    Test endpoint with authentication.

    *Requirements:* **AUTH**
    """

    return {"test": [1, 2, 3, 4, 5], "data": data}


@router.get("/auth/user", dependencies=[user_auth], responses=user_responses(list[int]))
async def test_auth() -> Any:
    """
    Test endpoint with authentication.

    *Requirements:* **USER**
    """

    return [2, 4, 6]
