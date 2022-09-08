from fastapi import APIRouter

from . import test


INTERNAL_ROUTERS: list[APIRouter] = [module.router for module in [test]]
