from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from iam_utils.auth import (
    apply_auth_cookie_delete_specs,
    apply_auth_cookie_specs,
    build_auth_cookie_delete_specs,
    build_auth_cookie_specs,
    can_sign_up_user,
    login_user,
    logout_session,
    refresh_session,
)
from iam_utils.sanitization import validate_password_strength
from iam_utils.security import get_password_hash, verify_password

from .crud import get_user_by_username, is_jti_revoked, revoke_jti, get_user_by_email
from .deps import USER_SCHEMA, get_db
from .models import User
from .schemas import LoginIn, MessageOut, SignUpIn


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/signup", response_model=MessageOut)
def signup(payload: SignUpIn, db: Session = Depends(get_db)) -> MessageOut:
    validate_password_strength(payload.password)

    if not can_sign_up_user(
        db=db,
        email=str(payload.email),
        get_user_by_email=lambda db, email: get_user_by_email(db, email),
    ):
        raise HTTPException(status_code=400, detail="Email already registered")

    if get_user_by_username(db, payload.username) is not None:
        raise HTTPException(status_code=400, detail="Username already registered")

    is_admin = payload.username.strip().lower() == "admin"

    user = User(
        login_name=payload.username,
        mail=str(payload.email),
        pwd_hash=get_password_hash(payload.password),
        active_flag=True,
        admin_flag=is_admin,
        perms="admin:read,admin:write,user:read" if is_admin else "user:read",
        role_names="admin" if is_admin else "user",
    )
    db.add(user)
    db.commit()
    return MessageOut(ok=True, detail="User created")


@router.post("/login", response_model=MessageOut)
def login(payload: LoginIn, response: Response, db: Session = Depends(get_db)) -> MessageOut:
    tokens = login_user(
        db=db,
        username=payload.username,
        email=str(payload.email) if payload.email is not None else None,
        password=payload.password,
        get_user_by_username=lambda db, username: get_user_by_username(db, username),
        get_user_by_email=lambda db, email: get_user_by_email(db, email),
        verify_password_fn=verify_password,
        user_schema=USER_SCHEMA,
        access_expires=timedelta(minutes=30),
        refresh_expires=timedelta(days=7),
    )
    if tokens is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    specs = build_auth_cookie_specs(
        tokens,
        secure=False,
        samesite="lax",
        refresh_path="/auth/refresh",
        set_max_age_from_exp=True,
    )
    apply_auth_cookie_specs(response.set_cookie, specs)
    return MessageOut(ok=True)


@router.post("/refresh", response_model=MessageOut)
def refresh(request: Request, response: Response, db: Session = Depends(get_db)) -> MessageOut:
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Missing refresh token")

    new_tokens = refresh_session(
        refresh_token,
        is_jti_revoked=lambda jti: is_jti_revoked(db, jti),
        revoke_jti=lambda jti, exp: revoke_jti(db, jti, exp),
    )
    if new_tokens is None:
        raise HTTPException(status_code=401, detail="Invalid refresh")

    specs = build_auth_cookie_specs(
        new_tokens,
        secure=False,
        samesite="lax",
        refresh_path="/auth/refresh",
        set_max_age_from_exp=True,
    )
    apply_auth_cookie_specs(response.set_cookie, specs)
    return MessageOut(ok=True)


@router.post("/logout", response_model=MessageOut)
def logout(request: Request, response: Response, db: Session = Depends(get_db)) -> MessageOut:
    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")

    if access_token or refresh_token:
        logout_session(
            revoke_jti=lambda jti, exp: revoke_jti(db, jti, exp),
            access_token=access_token,
            refresh_token=refresh_token,
        )

    delete_specs = build_auth_cookie_delete_specs(
        refresh_path="/auth/refresh",
    )
    apply_auth_cookie_delete_specs(response.delete_cookie, delete_specs)
    return MessageOut(ok=True)
