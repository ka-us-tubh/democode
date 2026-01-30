from __future__ import annotations

from typing import Generator

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from iam_utils.auth import UserSchema, require_user_from_access_token
from iam_utils.http import get_token_from_cookies, get_token_from_headers
from iam_utils.tokens import CredentialsError

from .crud import get_user_by_email, is_jti_revoked
from .db import SessionLocal
from .models import User


USER_SCHEMA = UserSchema(
    hashed_password_attr="pwd_hash",
    is_active_attr="active_flag",
    is_superuser_attr="admin_flag",
    permissions_attr="perms",
    roles_attr="role_names",
    username_attr="login_name",
    email_attr="mail",
    id_attr="user_id",
    subject_getter=lambda u: u.mail,
)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_user_by_subject(db: Session, subject: str) -> User | None:
    # Demo convention: we use email as the token subject.
    return get_user_by_email(db, subject)


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = get_token_from_cookies(request.cookies, cookie_name="access_token")
    if not token:
        token = get_token_from_headers(request.headers, header_name="Authorization")

    if not token:
        raise HTTPException(status_code=401, detail="Missing token")

    try:
        user = require_user_from_access_token(
            token,
            db=db,
            get_user_by_subject=lambda db, sub: get_user_by_subject(db, sub),
            is_jti_revoked=lambda jti: is_jti_revoked(db, jti),
            user_schema=USER_SCHEMA,
        )
    except CredentialsError:
        raise HTTPException(status_code=401, detail="Invalid token")

    return user
