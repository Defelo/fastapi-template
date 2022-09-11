from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, relationship

from .user import User
from ..database import Base, db, db_wrapper, delete
from ..logger import get_logger
from ..redis import redis
from ..settings import settings
from ..utils.jwt import decode_jwt, encode_jwt


logger = get_logger(__name__)


class SessionExpiredError(Exception):
    pass


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Session(Base):
    __tablename__ = "session"

    id: Mapped[str] = Column(String(36), primary_key=True, unique=True)
    user_id: Mapped[str] = Column(String(36), ForeignKey("user.id"))
    user: User = relationship("User", back_populates="sessions")
    device_name: Mapped[str] = Column(Text)
    last_update: Mapped[datetime] = Column(DateTime)
    refresh_token: Mapped[str] = Column(String(64), unique=True)

    @property
    def serialize(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "device_name": self.device_name,
            "last_update": self.last_update.timestamp(),
        }

    @staticmethod
    async def create(user_id: str, device_name: str) -> tuple[Session, str, str]:
        refresh_token = secrets.token_urlsafe(64)
        session = Session(
            id=str(uuid4()),
            user_id=user_id,
            device_name=device_name,
            last_update=datetime.utcnow(),
            refresh_token=_hash_token(refresh_token),
        )
        await db.add(session)
        return session, session._generate_access_token(), refresh_token

    def _generate_access_token(self) -> str:
        return encode_jwt(
            {"uid": self.user_id, "sid": self.id, "rt": self.refresh_token},
            timedelta(seconds=settings.access_token_ttl),
        )

    @staticmethod
    async def from_access_token(access_token: str) -> Session | None:
        if (data := decode_jwt(access_token, require=["uid", "sid", "rt"])) is None:
            return None
        if await redis.exists(f"session_logout:{data['rt']}"):
            return None

        return await db.get(Session, Session.user, id=data["sid"])

    @staticmethod
    async def refresh(refresh_token: str) -> tuple[Session, str, str]:
        token_hash = _hash_token(refresh_token)
        session: Session | None = await db.get(Session, Session.user, refresh_token=token_hash)
        if not session:
            raise ValueError("Invalid refresh token")
        if datetime.utcnow() > session.last_update + timedelta(seconds=settings.refresh_token_ttl):
            await session.logout()
            raise SessionExpiredError

        await redis.setex(f"session_logout:{session.refresh_token}", settings.access_token_ttl, 1)
        refresh_token = secrets.token_urlsafe(64)
        session.refresh_token = _hash_token(refresh_token)
        session.last_update = datetime.utcnow()
        return session, session._generate_access_token(), refresh_token

    async def logout(self) -> None:
        await redis.setex(f"session_logout:{self.refresh_token}", settings.access_token_ttl, 1)
        await db.delete(self)


@db_wrapper
async def clean_expired_sessions() -> None:
    await db.exec(
        delete(Session).where(Session.last_update < datetime.utcnow() - timedelta(seconds=settings.refresh_token_ttl))
    )
