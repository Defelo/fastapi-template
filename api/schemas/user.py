from pydantic import BaseModel, Field

from ..utils import example, get_example


USERNAME_REGEX = r"^[a-zA-Z0-9]{4,32}$"
PASSWORD_REGEX = r"^((?=.*[a-z])(?=.*[A-Z])(?=.*[0-9]).{8,})?$"  # noqa: S105
MFA_CODE_REGEX = r"^\d{6}$"


class User(BaseModel):
    id: str
    name: str
    registration: float
    last_login: float | None
    enabled: bool
    admin: bool
    password: bool
    mfa_enabled: bool

    Config = example(
        id="a13e63b1-9830-4604-8b7f-397d2c29955e",
        name="user42",
        registration=1615725447.182818,
        last_login=1615735459.274742,
        enabled=True,
        admin=False,
        password=True,
        mfa_enabled=False,
    )


class UsersResponse(BaseModel):
    total: int
    users: list[User]

    Config = example(total=1, users=[get_example(User)])


class CreateUser(BaseModel):
    name: str = Field(..., regex=USERNAME_REGEX)
    password: str | None = Field(None, regex=PASSWORD_REGEX)
    oauth_register_token: str | None
    recaptcha_response: str | None
    enabled: bool = True
    admin: bool = False


class UpdateUser(BaseModel):
    name: str | None = Field(None, regex=USERNAME_REGEX)
    password: str | None = Field(None, regex=PASSWORD_REGEX)
    enabled: bool | None
    admin: bool | None
