import uvicorn

from .app import app
from .environment import HOST, PORT, RELOAD, SENTRY_DSN
from .logger import setup_sentry, get_logger
from .version import get_version

logger = get_logger(__name__)


def main():
    if SENTRY_DSN:
        logger.debug("initializing sentry")
        setup_sentry(app, SENTRY_DSN, "FastAPI", get_version().description)

    uvicorn.run("api.app:app", host=HOST, port=PORT, reload=RELOAD)
