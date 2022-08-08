from unittest.mock import AsyncMock

from pytest_mock import MockerFixture

from api.models import OAuthUserConnection


async def test__serialize() -> None:
    obj = OAuthUserConnection(id="connection_id_123", provider_id="my_oauth_provider", display_name="Foo Bar")
    assert obj.serialize == {"id": "connection_id_123", "provider_id": "my_oauth_provider", "display_name": "Foo Bar"}


async def test__create(mocker: MockerFixture) -> None:
    db = mocker.patch("api.models.oauth_user_connection.db", new_callable=AsyncMock)

    obj = await OAuthUserConnection.create("user_id_123", "my_oauth_provider", "remote_user_id_123", "Foo Bar")

    assert obj.user_id == "user_id_123"
    assert obj.provider_id == "my_oauth_provider"
    assert obj.remote_user_id == "remote_user_id_123"
    assert obj.display_name == "Foo Bar"

    db.add.assert_called_once_with(obj)
