import jwt
from pydantic import BaseModel, Field

from .user import User
from ..utils import example, get_example


class Session(BaseModel):
    id: str = Field(description="Unique identifier for the session")
    user_id: str = Field(description="Unique identifier for the user")
    device_name: str = Field(description="Name of the device")
    last_update: float = Field(description="Timestamp of the last time an access token was created")

    Config = example(
        id="74193090-b88c-4984-9e51-da9cd3372e62",
        user_id=get_example(User)["id"],
        device_name="test device",
        last_update=1615725447.182818,
    )


class Login(BaseModel):
    name: str = Field(description="Unique username")
    password: str = Field(description="Password of the user")
    mfa_code: str | None = Field(description="MFA TOTP code")
    recovery_code: str | None = Field(description="Recovery code for MFA")
    recaptcha_response: str | None = Field(
        description="Recaptcha response (required if there have been too many failed login attempts)"
    )


class LoginResponse(BaseModel):
    user: User = Field(description="User that was logged in")
    session: Session = Field(description="Session that was created")
    access_token: str = Field(description="Access token that can be used to authenticate requests")
    refresh_token: str = Field(description="Refresh token that can be used to request a new access token")

    Config = example(  # noqa: S106
        user=get_example(User),
        session=get_example(Session),
        access_token=jwt.encode(
            {"user_id": get_example(User)["id"], "session_id": get_example(Session)["id"], "exp": 0}, "secret"
        ),
        refresh_token="KN4nF8BsiElQi_OoDYQ2BgVdhVirhTw67vOzfHutjONvazRXLsboZ__UG-oI-II3LoMNv9tgd6YBGYRGxNK7Ug",
    )


class OAuthLoginResponse(BaseModel):
    login: LoginResponse | None = Field(description="Login response if the user was successfully logged in")
    register_token: str | None = Field(
        description="OAuth registration token for user creation if no user is linked to the remote account yet"
    )
