from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import RevokedJTI, UsedJTI, User


def get_user_by_username(db: Session, username: str) -> User | None:
    return db.scalar(select(User).where(User.login_name == username))


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(User.mail == email))


def is_jti_revoked(db: Session, jti: str) -> bool:
    return db.scalar(select(RevokedJTI).where(RevokedJTI.jti == jti)) is not None


def revoke_jti(db: Session, jti: str, exp: datetime | None) -> None:
    existing = db.scalar(select(RevokedJTI).where(RevokedJTI.jti == jti))
    if existing is None:
        db.add(RevokedJTI(jti=jti, expires_at=exp))
        db.commit()


def is_jti_used(db: Session, jti: str) -> bool:
    return db.scalar(select(UsedJTI).where(UsedJTI.jti == jti)) is not None


def mark_jti_used(db: Session, jti: str, exp: datetime | None) -> None:
    existing = db.scalar(select(UsedJTI).where(UsedJTI.jti == jti))
    if existing is None:
        db.add(UsedJTI(jti=jti, expires_at=exp))
        db.commit()
