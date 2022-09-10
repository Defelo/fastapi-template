import uvicorn

from .logger import get_logger
from .settings import settings


get_logger(__name__)


def main() -> None:
    uvicorn.run("api.app:app", host=settings.host, port=settings.port, reload=settings.reload)
