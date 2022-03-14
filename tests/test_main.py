from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch, MagicMock

from api import main


class TestMain(IsolatedAsyncioTestCase):
    @patch("api.main.RELOAD")
    @patch("api.main.PORT")
    @patch("api.main.HOST")
    @patch("api.main.uvicorn")
    @patch("api.main.setup_app")
    async def test__main(
        self,
        setup_app_mock: MagicMock,
        uvicorn_mock: MagicMock,
        host_mock: MagicMock,
        port_mock: MagicMock,
        reload_mock: MagicMock,
    ) -> None:
        main.main()
        setup_app_mock.assert_called_once_with()
        uvicorn_mock.run.assert_called_once_with("api.app:app", host=host_mock, port=port_mock, reload=reload_mock)

    @patch("api.main.get_version")
    @patch("api.main.app")
    @patch("api.main.setup_sentry")
    @patch("api.main.SENTRY_DSN")
    @patch("api.main.RELOAD")
    @patch("api.main.PORT")
    @patch("api.main.HOST")
    @patch("api.main.uvicorn")
    @patch("api.main.setup_app")
    async def test__main__sentry(
        self,
        setup_app_mock: MagicMock,
        uvicorn_mock: MagicMock,
        host_mock: MagicMock,
        port_mock: MagicMock,
        reload_mock: MagicMock,
        sentry_dsn_mock: MagicMock,
        setup_sentry_mock: MagicMock,
        app_mock: MagicMock,
        get_version_mock: MagicMock,
    ) -> None:
        main.main()

        setup_sentry_mock.assert_called_once_with(app_mock, sentry_dsn_mock, "FastAPI", get_version_mock().description)
        setup_app_mock.assert_called_once_with()
        uvicorn_mock.run.assert_called_once_with("api.app:app", host=host_mock, port=port_mock, reload=reload_mock)
