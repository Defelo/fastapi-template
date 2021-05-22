from fastapi import FastAPI

from environment import SENTRY_DSN
from logger import setup_sentry, get_logger

logger = get_logger(__name__)
get_logger("uvicorn")

app = FastAPI()

if SENTRY_DSN:
    logger.debug("initializing sentry")
    setup_sentry(app, SENTRY_DSN, "fastapi", "1.0.0")


@app.on_event("startup")
async def on_startup():
    pass


@app.on_event("shutdown")
async def on_shutdown():
    pass


@app.get("/test")
async def test():
    return {"result": "hello world"}
