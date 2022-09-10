import sys
from logging import PercentStyle, StreamHandler

from _pytest.monkeypatch import MonkeyPatch
from pytest_mock import MockerFixture
from uvicorn.config import LOGGING_CONFIG
from uvicorn.logging import DefaultFormatter

from ._utils import mock_list
from api import logger
from api.settings import settings


async def test__setup_sentry(mocker: MockerFixture) -> None:
    ignore_logger_patch = mocker.patch("api.logger.ignore_logger")
    loggingintegration_patch = mocker.patch("api.logger.LoggingIntegration")
    sqlalchemyintegration_patch = mocker.patch("api.logger.SqlalchemyIntegration")
    aiohttpintegration_patch = mocker.patch("api.logger.AioHttpIntegration")
    logging_patch = mocker.patch("api.logger.logging")
    sentry_sdk_init_patch = mocker.patch("api.logger.sentry_sdk.init")

    app, dsn, name, version = mock_list(4)

    logger.setup_sentry(app, dsn, name, version)

    aiohttpintegration_patch.assert_called_once_with()
    sqlalchemyintegration_patch.assert_called_once_with()
    loggingintegration_patch.assert_called_once_with(level=logging_patch.DEBUG, event_level=logging_patch.WARNING)
    sentry_sdk_init_patch.assert_called_once_with(
        dsn=dsn,
        attach_stacktrace=True,
        shutdown_timeout=5,
        integrations=[aiohttpintegration_patch(), sqlalchemyintegration_patch(), loggingintegration_patch()],
        release=f"{name}@{version}",
    )
    ignore_logger_patch.assert_called_once_with("uvicorn.error")


async def test__logging_formatter() -> None:
    assert isinstance(logger.logging_formatter, DefaultFormatter)
    assert logger.logging_formatter._fmt == "[%(asctime)s] %(levelprefix)s %(message)s"
    assert LOGGING_CONFIG["formatters"]["default"]["fmt"] == "[%(asctime)s] %(levelprefix)s %(message)s"
    assert (
        LOGGING_CONFIG["formatters"]["access"]["fmt"]
        == '[%(asctime)s] %(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s'
    )
    assert isinstance(logger.logging_formatter._style, PercentStyle)


async def test__logging_handler() -> None:
    assert isinstance(logger.logging_handler, StreamHandler)
    assert sys.stdout is logger.logging_handler.stream
    assert logger.logging_formatter is logger.logging_handler.formatter


async def test__get_logger(monkeypatch: MonkeyPatch, mocker: MockerFixture) -> None:
    monkeypatch.setattr(settings, "log_level", "MY_LOG_LEVEL")
    getlogger_patch = mocker.patch("api.logger.logging.getLogger")
    logging_handler_patch = mocker.patch("api.logger.logging_handler")

    result = logger.get_logger("my_logger")

    getlogger_patch.assert_called_once_with("my_logger")
    getlogger_patch().addHandler.assert_called_once_with(logging_handler_patch)
    getlogger_patch().setLevel.assert_called_once_with("MY_LOG_LEVEL")
    assert result == getlogger_patch()
