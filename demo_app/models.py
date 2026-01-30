from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    user_id: Mapped[int] = mapped_column("user_id", Integer, primary_key=True)
    login_name: Mapped[str] = mapped_column("login", String(150), unique=True, index=True)
    mail: Mapped[str] = mapped_column("mail", String(320), unique=True, index=True)
    pwd_hash: Mapped[str] = mapped_column("pwd_hash", Text)

    active_flag: Mapped[bool] = mapped_column("active", Boolean, default=True)
    admin_flag: Mapped[bool] = mapped_column("admin", Boolean, default=False)
    perms: Mapped[str] = mapped_column("perms", Text, default="")
    role_names: Mapped[str] = mapped_column("role_names", Text, default="")
    sec_answer_hash: Mapped[str | None] = mapped_column("sec_answer_hash", Text, nullable=True)


class RevokedJTI(Base):
    __tablename__ = "revoked_jtis"

    jti: Mapped[str] = mapped_column(String(255), primary_key=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class UsedJTI(Base):
    __tablename__ = "used_jtis"

    jti: Mapped[str] = mapped_column(String(255), primary_key=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
