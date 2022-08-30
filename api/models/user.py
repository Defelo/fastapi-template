from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, String, func
from sqlalchemy.orm import Mapped, relationship
from sqlalchemy.sql import Select

from ..database import Base, db, select
from ..environment import ADMIN_PASSWORD, ADMIN_USERNAME
from ..logger import get_logger
from ..redis import redis
from ..utils.jwt import decode_jwt
from ..utils.passwords import hash_password, verify_password


if TYPE_CHECKING:
    from .oauth_user_connection import OAuthUserConnection
    from .session import Session

logger = get_logger(__name__)


class User(Base):
    __tablename__ = "user"

    id: Mapped[str] = Column(String(36), primary_key=True, unique=True)
    name: Mapped[str] = Column(String(32), unique=True)
    password: Mapped[str | None] = Column(String(128), nullable=True)
    registration: Mapped[datetime] = Column(DateTime)
    last_login: Mapped[datetime | None] = Column(DateTime, nullable=True)
    enabled: Mapped[bool] = Column(Boolean, default=True)
    admin: Mapped[bool] = Column(Boolean, default=False)
    mfa_secret: Mapped[str | None] = Column(String(32), nullable=True)
    mfa_enabled: Mapped[bool] = Column(Boolean, default=False)
    mfa_recovery_code: Mapped[str | None] = Column(String(64), nullable=True)
    sessions: list[Session] = relationship("Session", back_populates="user", cascade="all, delete")
    oauth_connections: list[OAuthUserConnection] = relationship(
        "OAuthUserConnection", back_populates="user", cascade="all, delete"
    )

    @property
    def serialize(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "registration": self.registration.timestamp(),
            "last_login": self.last_login.timestamp() if self.last_login else None,
            "enabled": self.enabled,
            "admin": self.admin,
            "password": bool(self.password),
            "mfa_enabled": self.mfa_enabled,
        }

    @staticmethod
    async def create(name: str, password: str | None, enabled: bool, admin: bool) -> User:
        user = User(
            id=str(uuid4()),
            name=name,
            password=await hash_password(password) if password else None,
            registration=datetime.utcnow(),
            last_login=None,
            enabled=enabled,
            admin=admin,
            mfa_secret=None,
            mfa_enabled=False,
            mfa_recovery_code=None,
        )
        await db.add(user)
        return user

    @staticmethod
    def filter_by_name(name: str) -> Select:
        return select(User).where(func.lower(User.name) == name.lower())

    @staticmethod
    async def initialize() -> None:
        if await db.exists(select(User)):
            return

        await User.create(ADMIN_USERNAME, ADMIN_PASSWORD, True, True)
        logger.info(f"Admin user '{ADMIN_USERNAME}' has been created!")

    async def check_password(self, password: str) -> bool:
        if not self.password:
            return False

        return await verify_password(password, self.password)

    async def change_password(self, password: str | None) -> None:
        self.password = await hash_password(password) if password else None

    async def create_session(self, device_name: str) -> tuple[Session, str, str]:
        from .session import Session

        self.last_login = datetime.utcnow()
        return await Session.create(self.id, device_name)

    @staticmethod
    async def from_access_token(access_token: str) -> User | None:
        if (data := decode_jwt(access_token, ["uid", "sid", "rt"])) is None:
            return None
        if await redis.exists(f"session_logout:{data['rt']}"):
            return None

        return await db.get(User, id=data["uid"], enabled=True)

    async def logout(self) -> None:
        for session in self.sessions:
            await session.logout()
