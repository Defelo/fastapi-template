import uvicorn

from .environment import HOST, PORT, RELOAD
from .logger import get_logger


get_logger(__name__)


def main() -> None:
    uvicorn.run("api.app:app", host=HOST, port=PORT, reload=RELOAD)
