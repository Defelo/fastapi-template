from pydantic import BaseModel

from ..utils import example


class OAuthProvider(BaseModel):
    id: str
    name: str
    authorize_url: str

    Config = example(id="github", name="GitHub", authorize_url="https://github.com/login/oauth/authorize")


class OAuthConnection(BaseModel):
    id: str
    provider_id: str
    display_name: str | None


class OAuthLogin(BaseModel):
    provider_id: str
    code: str
    redirect_uri: str
