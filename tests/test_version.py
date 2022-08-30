from _pytest.capture import CaptureFixture
from pytest_mock import MockerFixture

from ._utils import run_module
from api import version


async def test__get_version(mocker: MockerFixture) -> None:
    getoutput_patch = mocker.patch("subprocess.getoutput")
    getoutput_patch.return_value = "2d70111\ndevelop\nv1.0.0"

    result = version.get_version()

    getoutput_patch.assert_called_once_with(
        "(git rev-parse HEAD && (git symbolic-ref --short HEAD || echo) && git describe --tags --always) "
        "2> /dev/null || cat VERSION"
    )
    assert result == version.Version(commit="2d70111", branch="develop", description="v1.0.0")


async def test__main(capsys: CaptureFixture[str], mocker: MockerFixture) -> None:
    getoutput_patch = mocker.patch("subprocess.getoutput")
    getoutput_patch.return_value = "2d70111\ndevelop\nv1.0.0"

    run_module(version)

    getoutput_patch.assert_called_once_with(
        "(git rev-parse HEAD && (git symbolic-ref --short HEAD || echo) && git describe --tags --always) "
        "2> /dev/null | tee VERSION"
    )
    assert capsys.readouterr().out.strip() == getoutput_patch()
