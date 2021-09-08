import uvicorn

from .environment import HOST, PORT, RELOAD, SENTRY_DSN
from .app import app
from .logger import setup_sentry, get_logger

logger = get_logger(__name__)


def main():
    if SENTRY_DSN:
        logger.debug("initializing sentry")
        setup_sentry(app, SENTRY_DSN, "fastapi", "1.0.0")

    uvicorn.run("api.app:app", host=HOST, port=PORT, reload=RELOAD)
