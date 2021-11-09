from typing import Optional

from pydantic import BaseModel, constr

from ..utils import example, get_example

USERNAME_REGEX = r"^[a-zA-Z0-9]{4,32}$"
PASSWORD_REGEX = r"^((?=.*[a-z])(?=.*[A-Z])(?=.*[0-9]).{8,})?$"
MFA_CODE_REGEX = r"^\d{6}$"

user_constr = constr(regex=USERNAME_REGEX)
password_constr = constr(regex=PASSWORD_REGEX)
mfa_code_constr = constr(regex=MFA_CODE_REGEX)


class User(BaseModel):
    id: str
    name: str
    registration: float
    enabled: bool
    admin: bool
    password: bool
    mfa_enabled: bool

    Config = example(
        id="a13e63b1-9830-4604-8b7f-397d2c29955e",
        name="user42",
        registration=1615725447.182818,
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
    name: user_constr
    password: Optional[password_constr]
    oauth_register_token: Optional[str]
    enabled: bool = True
    admin: bool = False


class UpdateUser(BaseModel):
    name: Optional[user_constr]
    password: Optional[password_constr]
    enabled: Optional[bool]
    admin: Optional[bool]
