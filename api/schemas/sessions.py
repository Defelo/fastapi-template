from typing import Optional

import jwt
from pydantic import BaseModel

from .user import User
from ..utils import example, get_example


class Session(BaseModel):
    id: str
    user_id: str
    device_name: str
    last_update: float

    Config = example(
        id="74193090-b88c-4984-9e51-da9cd3372e62",
        user_id=get_example(User)["id"],
        device_name="test device",
        last_update=1615725447.182818,
    )


class Login(BaseModel):
    name: str
    password: str
    mfa_code: Optional[str] = ""
    recovery_code: Optional[str] = ""


class LoginResponse(BaseModel):
    user: User
    session: Session
    access_token: str
    refresh_token: str

    Config = example(
        user=get_example(User),
        session=get_example(Session),
        access_token=jwt.encode(
            {"user_id": get_example(User)["id"], "session_id": get_example(Session)["id"], "exp": 0},
            "secret",
        ),
        refresh_token="KN4nF8BsiElQi_OoDYQ2BgVdhVirhTw67vOzfHutjONvazRXLsboZ__UG-oI-II3LoMNv9tgd6YBGYRGxNK7Ug",
    )
