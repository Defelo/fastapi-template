from __future__ import annotations

from typing import Union, Optional
from uuid import uuid4

from sqlalchemy import Column, String, Text, ForeignKey
from sqlalchemy.orm import relationship

from .user import User
from ..database import db


class OAuthUserConnection(db.Base):
    __tablename__ = "oauth_user_connection"

    id: Union[Column, str] = Column(String(36), primary_key=True, unique=True)
    user_id: Union[Column, str] = Column(String(36), ForeignKey("user.id"))
    user: User = relationship("User", back_populates="oauth_connections")
    provider_id: Union[Column, str] = Column(String(64))
    remote_user_id: Union[Column, str] = Column(Text(collation="utf8mb4_bin"))
    display_name: Union[Column, Optional[str]] = Column(Text(collation="utf8mb4_bin"), nullable=True)

    @property
    def serialize(self) -> dict:
        return {
            "id": self.id,
            "provider_id": self.provider_id,
            "display_name": self.display_name,
        }

    @staticmethod
    async def create(
        user_id: str,
        provider_id: str,
        remote_user_id: str,
        display_name: Optional[str],
    ) -> OAuthUserConnection:
        row = OAuthUserConnection(
            id=str(uuid4()),
            user_id=user_id,
            provider_id=provider_id,
            remote_user_id=remote_user_id,
            display_name=display_name,
        )
        await db.add(row)
        return row
