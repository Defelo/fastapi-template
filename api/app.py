from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from .database import db
from .endpoints import test
from .environment import ROOT_PATH, DEBUG
from .logger import get_logger
from .version import get_version

logger = get_logger(__name__)

app = FastAPI(title="FastAPI", version=get_version().description, root_path=ROOT_PATH)

if DEBUG:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


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


app.include_router(test.router)
