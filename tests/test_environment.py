import os
import re

import jq
import pytest
from _pytest.monkeypatch import MonkeyPatch

from .utils import import_module
from api.environment import OAuthProvider


@pytest.mark.parametrize(
    "providers",
    [
        {},
        {
            "github": OAuthProvider(
                "GitHub",
                "asdf",
                "jklö",
                "https://github.com/login/oauth/authorize",
                "https://github.com/login/oauth/access_token",
                "https://api.github.com/user",
                "Authorization=Bearer%20{access_token}",
                ".id",
                ".login",
            ),
            "asdf": OAuthProvider("", "", "", "", "", "", "", "", ""),
        },
    ],
)
async def test__oauth_providers(providers: dict[str, OAuthProvider], monkeypatch: MonkeyPatch) -> None:
    for var in os.environ:
        if re.match(r"^OAUTH_([A-Z\d_]+)_CLIENT_ID$", var):
            monkeypatch.delenv(var)

    for provider_id, provider in providers.items():
        monkeypatch.setenv(f"OAUTH_{provider_id.upper()}_NAME", provider.name)
        monkeypatch.setenv(f"OAUTH_{provider_id.upper()}_CLIENT_ID", provider.client_id)
        monkeypatch.setenv(f"OAUTH_{provider_id.upper()}_CLIENT_SECRET", provider.client_secret)
        monkeypatch.setenv(f"OAUTH_{provider_id.upper()}_AUTHORIZE_URL", provider.authorize_url)
        monkeypatch.setenv(f"OAUTH_{provider_id.upper()}_TOKEN_URL", provider.token_url)
        monkeypatch.setenv(f"OAUTH_{provider_id.upper()}_USERINFO_URL", provider.userinfo_url)
        monkeypatch.setenv(f"OAUTH_{provider_id.upper()}_USERINFO_HEADERS", provider.userinfo_headers)
        monkeypatch.setenv(f"OAUTH_{provider_id.upper()}_USERINFO_ID_PATH", provider.user_id_path)
        monkeypatch.setenv(f"OAUTH_{provider_id.upper()}_USERINFO_NAME_PATH", provider.display_name_path)

    module = import_module("api.environment")

    assert {
        k: OAuthProvider(
            **{
                **v._asdict(),
                "user_id_path": v.user_id_path.program_string,
                "display_name_path": v.display_name_path.program_string,
            }
        )
        for k, v in module.OAUTH_PROVIDERS.items()
    } == {k: v for k, v in providers.items() if all(v._asdict().values())}
