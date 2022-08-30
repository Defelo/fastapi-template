from pydantic import BaseModel, Field

from ..utils.docs import example, get_example


USERNAME_REGEX = r"^[a-zA-Z0-9]{4,32}$"
PASSWORD_REGEX = r"^((?=.*[a-z])(?=.*[A-Z])(?=.*[0-9]).{8,})?$"  # noqa: S105
MFA_CODE_REGEX = r"^\d{6}$"


class User(BaseModel):
    id: str = Field(description="Unique identifier for the user")
    name: str = Field(description="Unique username")
    registration: float = Field(description="Timestamp of the user's registration")
    last_login: float | None = Field(description="Timestamp of the user's last successful login")
    enabled: bool = Field(description="Whether the user is enabled")
    admin: bool = Field(description="Whether the user is an administrator")
    password: bool = Field(description="Whether the user has a password (if not, login is only possible via OAuth)")
    mfa_enabled: bool = Field(description="Whether the user has enabled MFA")

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
    total: int = Field(description="Total number of users matching the query")
    users: list[User] = Field(description="Paginated list of users matching the query")

    Config = example(total=1, users=[get_example(User)])


class CreateUser(BaseModel):
    name: str = Field(regex=USERNAME_REGEX, description="Unique username")
    password: str | None = Field(regex=PASSWORD_REGEX, description="Password of the user")
    oauth_register_token: str | None = Field(description="OAuth registration token returned by `POST /sessions/oauth`")
    recaptcha_response: str | None = Field(description="Recaptcha response (required if not requested by an admin)")
    enabled: bool = Field(True, description="Whether the user is enabled")
    admin: bool = Field(False, description="Whether the user is an administrator")


class UpdateUser(BaseModel):
    name: str | None = Field(regex=USERNAME_REGEX, description="Change the username")
    password: str | None = Field(
        regex=PASSWORD_REGEX, description="Change the password (if set to `null`, the password is removed)"
    )
    enabled: bool | None = Field(description="Change whether the user is enabled")
    admin: bool | None = Field(description="Change whether the user is an administrator")
