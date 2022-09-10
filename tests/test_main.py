from _pytest.monkeypatch import MonkeyPatch
from pytest_mock import MockerFixture

from api import main
from api.settings import settings


async def test__main(mocker: MockerFixture, monkeypatch: MonkeyPatch) -> None:
    run_patch = mocker.patch("uvicorn.run")
    monkeypatch.setattr(settings, "host", "1.2.3.4")
    monkeypatch.setattr(settings, "port", 8023)
    monkeypatch.setattr(settings, "reload", True)

    main.main()

    run_patch.assert_called_once_with("api.app:app", host="1.2.3.4", port=8023, reload=True)
