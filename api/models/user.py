from __future__ import annotations

from datetime import datetime
from typing import Union, Optional, TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import Column, String, DateTime, Boolean
from sqlalchemy.orm import relationship

from ..database import db, select
from ..environment import ADMIN_USERNAME, ADMIN_PASSWORD
from ..logger import get_logger
from ..redis import redis
from ..utils import hash_password, verify_password, decode_jwt

if TYPE_CHECKING:
    from .session import Session

logger = get_logger(__name__)


class User(db.Base):
    __tablename__ = "user"

    id: Union[Column, str] = Column(String(36), primary_key=True, unique=True)
    name: Union[Column, str] = Column(String(32), unique=True)
    password: Union[Column, Optional[str]] = Column(String(128), nullable=True)
    registration: Union[Column, datetime] = Column(DateTime)
    enabled: Union[Column, bool] = Column(Boolean, default=True)
    admin: Union[Column, bool] = Column(Boolean, default=False)
    mfa_secret: Union[Column, Optional[str]] = Column(String(32), nullable=True)
    mfa_enabled: Union[Column, bool] = Column(Boolean, default=False)
    mfa_recovery_code: Union[Column, Optional[str]] = Column(String(64), nullable=True)
    sessions: list[Session] = relationship("Session", back_populates="user", cascade="all, delete")

    @staticmethod
    async def create(name: str, password: str, enabled: bool, admin: bool) -> User:
        user = User(
            id=str(uuid4()),
            name=name,
            password=await hash_password(password),
            registration=datetime.utcnow(),
            enabled=enabled,
            admin=admin,
            mfa_secret=None,
            mfa_enabled=False,
            mfa_recovery_code=None,
        )
        await db.add(user)
        return user

    @staticmethod
    async def initialize():
        if await db.exists(select(User)):
            return

        await User.create(ADMIN_USERNAME, ADMIN_PASSWORD, True, True)
        logger.info(f"Admin user '{ADMIN_USERNAME}' has been created!")

    @property
    def serialize(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "registration": self.registration.timestamp(),
            "enabled": self.enabled,
            "admin": self.admin,
            "mfa_enabled": self.mfa_enabled,
        }

    async def check_password(self, password) -> bool:
        return await verify_password(password, self.password)

    async def change_password(self, password):
        self.password = await hash_password(password)

    @staticmethod
    async def authenticate(name: str, password: str) -> Optional[User]:
        user: Optional[User] = await db.get(User, name=name)
        if not user or not user.enabled or not await user.check_password(password):
            return None

        return user

    async def create_session(self, device_name: str) -> tuple[Session, str, str]:
        from .session import Session

        return await Session.create(self.id, device_name)

    @staticmethod
    async def from_access_token(access_token: str) -> Optional[User]:
        if (data := decode_jwt(access_token, ["uid", "sid", "rt"])) is None:
            return None
        if await redis.exists(f"session_logout:{data['rt']}"):
            return None

        return await db.get(User, id=data["uid"], enabled=True)

    async def logout(self):
        for session in self.sessions:
            await session.logout()
