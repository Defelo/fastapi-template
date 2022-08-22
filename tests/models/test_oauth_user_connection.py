from api.database import db, db_wrapper, select
from api.models import OAuthUserConnection


async def test__serialize() -> None:
    obj = OAuthUserConnection(id="connection_id_123", provider_id="my_oauth_provider", display_name="Foo Bar")
    assert obj.serialize == {"id": "connection_id_123", "provider_id": "my_oauth_provider", "display_name": "Foo Bar"}


@db_wrapper
async def test__create() -> None:
    obj = await OAuthUserConnection.create("user_id_123", "my_oauth_provider", "remote_user_id_123", "Foo Bar")
    connections = await db.all(select(OAuthUserConnection))
    assert connections == [obj]

    assert obj.user_id == "user_id_123"
    assert obj.provider_id == "my_oauth_provider"
    assert obj.remote_user_id == "remote_user_id_123"
    assert obj.display_name == "Foo Bar"
