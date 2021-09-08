from fastapi import FastAPI, Request

from .database import db
from .logger import get_logger

logger = get_logger(__name__)

app = FastAPI()


@app.middleware("http")
async def db_session(request: Request, call_next):
    db.create_session()
    try:
        return await call_next(request)
    finally:
        await db.commit()
        await db.close()


@app.on_event("startup")
async def on_startup():
    await db.create_tables()


@app.on_event("shutdown")
async def on_shutdown():
    pass


@app.get("/test")
async def test():
    return {"result": "hello world"}
