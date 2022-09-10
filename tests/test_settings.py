import pytest

from api.settings import OAuthProvider


@pytest.fixture()
def oauth_provider() -> OAuthProvider:
    return OAuthProvider.parse_obj(
        {
            "name": "test",
            "client_id": "test_id",
            "client_secret": "test_secret",
            "authorize_url": "test_authorize_url",
            "token_url": "test_token_url",
            "userinfo_url": "test_userinfo_url",
            "userinfo_headers": '{"foo":"bar","test":"hello world"}',
            "userinfo_id_path": ".id",
            "userinfo_name_path": ".name",
        }
    )


async def test__oauth_provider__validate_userinfo_headers(oauth_provider: OAuthProvider) -> None:
    assert oauth_provider.userinfo_headers == {"foo": "bar", "test": "hello world"}


async def test__oauth_provider__validate_userinfo_id_path(oauth_provider: OAuthProvider) -> None:
    assert oauth_provider.userinfo_id_path.input({"id": 42, "name": "test"}).first() == 42


async def test__oauth_provider__validate_userinfo_name_path(oauth_provider: OAuthProvider) -> None:
    assert oauth_provider.userinfo_name_path.input({"id": 42, "name": "test"}).first() == "test"
