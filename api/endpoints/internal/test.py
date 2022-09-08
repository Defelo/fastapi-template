from fastapi import APIRouter

from api.exceptions.auth import internal_responses


router = APIRouter()


@router.get("/test", responses=internal_responses(str))
async def internal_test() -> str:
    return "ok"
