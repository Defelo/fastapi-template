from pydantic import BaseModel, Field

from ..utils import example


class OAuthProvider(BaseModel):
    id: str = Field(description="Unique identifier for the OAuth provider")
    name: str = Field(description="Name of the OAuth provider")
    authorize_url: str = Field(description="URL of the OAuth provider's authorize endpoint")

    Config = example(id="github", name="GitHub", authorize_url="https://github.com/login/oauth/authorize")


class OAuthConnection(BaseModel):
    id: str = Field(description="Unique identifier for the OAuth connection")
    provider_id: str = Field(description="Unique identifier for the OAuth provider")
    display_name: str | None = Field(description="Display name of the remote user")


class OAuthLogin(BaseModel):
    provider_id: str = Field(description="Unique identifier for the OAuth provider")
    code: str = Field(description="Authorization code returned by the OAuth provider")
    redirect_uri: str = Field(description="Redirect URI that was used to obtain the authorization code")
