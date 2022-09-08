from typing import Any

from fastapi import APIRouter

from . import test
from .internal import INTERNAL_ROUTERS
from ..auth import jwt_auth


ROUTER = APIRouter()
TAGS: list[dict[str, Any]] = []


for module in [test]:
    name = module.__name__.split(".")[-1]
    router = APIRouter(tags=[name])
    router.include_router(module.router)
    ROUTER.include_router(router)

    TAGS.append({"name": name, "description": module.__doc__ or ""})

TAGS.append({"name": "internal", "description": "Internal endpoints"})

for r in INTERNAL_ROUTERS:
    router = APIRouter(prefix="/_internal", tags=["internal"], dependencies=[jwt_auth])
    router.include_router(r)
    ROUTER.include_router(router)
