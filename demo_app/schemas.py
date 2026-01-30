from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

class SignUpIn(BaseModel):
    username: str
    email: str
    password: str


class LoginIn(BaseModel):
    username: str | None = None
    email: str | None = None
    password: str


class MessageOut(BaseModel):
    ok: bool
    detail: str | None = None


class UserOut(BaseModel):
    username: str
    email: str
    is_active: bool
    is_superuser: bool
    permissions: str
    roles: str


class UpdateUserAuthzIn(BaseModel):
    email: str
    permissions: str | None = None
    roles: str | None = None
    is_superuser: bool | None = None
    is_active: bool | None = None


class TokenIn(BaseModel):
    token: str


class TokenOut(BaseModel):
    jti: str | None = None
    exp: datetime | None = None


class OriginCheckIn(BaseModel):
    origin: str | None = None
    allowed_origins: list[str]
    allow_null_origin: bool = False


class SecurityQuestionSetIn(BaseModel):
    email: str
    answer_hash: str


class SecurityAnswerIn(BaseModel):
    answer: str


class SecurityAnswerHashOut(BaseModel):
    answer_hash: str
