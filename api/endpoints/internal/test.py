from fastapi import APIRouter

from api.exceptions.auth import InvalidTokenError
from api.utils.docs import responses


router = APIRouter()


@router.get("/test", responses=responses(str, InvalidTokenError))
async def internal_test() -> str:
    return "ok"
