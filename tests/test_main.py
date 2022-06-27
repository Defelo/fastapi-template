from unittest import IsolatedAsyncioTestCase
from unittest.mock import MagicMock, patch

from api import main


class TestMain(IsolatedAsyncioTestCase):
    @patch("api.main.RELOAD")
    @patch("api.main.PORT")
    @patch("api.main.HOST")
    @patch("api.main.uvicorn")
    async def test__main(
        self, uvicorn_mock: MagicMock, host_mock: MagicMock, port_mock: MagicMock, reload_mock: MagicMock
    ) -> None:
        main.main()

        uvicorn_mock.run.assert_called_once_with("api.app:app", host=host_mock, port=port_mock, reload=reload_mock)
