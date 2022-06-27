from unittest import IsolatedAsyncioTestCase
from unittest.mock import MagicMock, patch

from api import version

from utils import run_module


class TestVersion(IsolatedAsyncioTestCase):
    @patch("subprocess.getoutput")
    async def test__get_version(self, getoutput_patch: MagicMock) -> None:
        getoutput_patch.return_value = "2d70111eb8ac7c92de7e1dec7531d64e8dd2e48f\ndevelop\nv1.0.0"

        result = version.get_version()

        getoutput_patch.assert_called_once_with(
            "(git rev-parse HEAD && (git symbolic-ref --short HEAD || echo) && git describe --tags --always) "
            "2> /dev/null || cat VERSION"
        )
        self.assertEqual(
            version.Version(commit="2d70111eb8ac7c92de7e1dec7531d64e8dd2e48f", branch="develop", description="v1.0.0"),
            result,
        )

    @patch("builtins.print")
    @patch("subprocess.getoutput")
    async def test__main(self, getoutput_patch: MagicMock, print_patch: MagicMock) -> None:
        run_module("api.version")

        getoutput_patch.assert_called_once_with(
            "(git rev-parse HEAD && (git symbolic-ref --short HEAD || echo) && git describe --tags --always) "
            "2> /dev/null | tee VERSION"
        )
        print_patch.assert_called_once_with(getoutput_patch())
