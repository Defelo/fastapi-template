from _pytest.monkeypatch import MonkeyPatch
from pytest_mock import MockerFixture

from .utils import reload_module
from api import environment, main


async def test__main(mocker: MockerFixture, monkeypatch: MonkeyPatch) -> None:
    run_patch = mocker.patch("uvicorn.run")
    monkeypatch.setenv("HOST", "1.2.3.4")
    monkeypatch.setenv("PORT", "8023")
    monkeypatch.setenv("RELOAD", "true")
    reload_module(environment)

    reload_module(main).main()

    run_patch.assert_called_once_with("api.app:app", host="1.2.3.4", port=8023, reload=True)
