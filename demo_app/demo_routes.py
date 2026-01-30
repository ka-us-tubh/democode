from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from iam_utils.auth import (
    PermissionDeniedError,
    ensure_user_has_any_permission,
    ensure_user_has_effective_permissions,
    ensure_user_has_permissions,
    ensure_user_is_superuser,
    verify_security_question_challenge,
)
from iam_utils.middleware import OriginError, apply_security_headers, validate_origin
from iam_utils.rbac import user_effective_permissions
from iam_utils.security_questions import hash_security_answer
from iam_utils.tokens import (
    consume_one_time_token,
    decode_access_token,
    get_token_exp,
    get_token_jti,
)

from .crud import (
    get_user_by_username,
    get_user_by_email,
    is_jti_used,
    mark_jti_used,
)
from .deps import USER_SCHEMA, get_current_user, get_db
from .schemas import (
    MessageOut,
    OriginCheckIn,
    SecurityAnswerHashOut,
    SecurityAnswerIn,
    SecurityQuestionSetIn,
    TokenIn,
    TokenOut,
    UpdateUserAuthzIn,
)
from .models import User


router = APIRouter(prefix="/demo", tags=["demo"])


_ROLE_TO_PERMS = {
    "user": ["user:read"],
    "admin": ["admin:read", "admin:write", "user:read"],
}


def _get_user_by_email_or_404(db: Session, email: str) -> User:
    user = get_user_by_email(db, email)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.get("/authz/effective-permissions", response_model=dict)
def effective_permissions(user: User = Depends(get_current_user)) -> dict:
    perms = user_effective_permissions(
        user,
        role_to_permissions=_ROLE_TO_PERMS,
        permissions_attr=USER_SCHEMA.permissions_attr,
        roles_attr=USER_SCHEMA.roles_attr,
    )
    return {"effective_permissions": sorted(perms)}


@router.post("/authz/update-user", response_model=MessageOut)
def update_user_authz(
    payload: UpdateUserAuthzIn,
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MessageOut:
    try:
        ensure_user_is_superuser(current, attr=USER_SCHEMA.is_superuser_attr)
    except PermissionDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    target = _get_user_by_email_or_404(db, str(payload.email))
    if payload.permissions is not None:
        target.perms = payload.permissions
    if payload.roles is not None:
        target.role_names = payload.roles
    if payload.is_superuser is not None:
        target.admin_flag = payload.is_superuser
    if payload.is_active is not None:
        target.active_flag = payload.is_active

    db.add(target)
    db.commit()

    return MessageOut(ok=True)


@router.get("/authz/require-perms", response_model=MessageOut)
def require_perms(
    required: str,
    user: User = Depends(get_current_user),
) -> MessageOut:
    required_list = [p.strip() for p in required.split(",") if p.strip()]
    try:
        ensure_user_has_permissions(user, required_list, attr=USER_SCHEMA.permissions_attr)
    except PermissionDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    return MessageOut(ok=True)


@router.get("/authz/require-any-perm", response_model=MessageOut)
def require_any_perm(
    required: str,
    user: User = Depends(get_current_user),
) -> MessageOut:
    required_list = [p.strip() for p in required.split(",") if p.strip()]
    try:
        ensure_user_has_any_permission(user, required_list, attr=USER_SCHEMA.permissions_attr)
    except PermissionDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    return MessageOut(ok=True)


@router.get("/authz/require-effective", response_model=MessageOut)
def require_effective(
    required: str,
    any_: bool = False,
    user: User = Depends(get_current_user),
) -> MessageOut:
    required_list = [p.strip() for p in required.split(",") if p.strip()]
    try:
        ensure_user_has_effective_permissions(
            user,
            required_list,
            role_to_permissions=_ROLE_TO_PERMS,
            any_=any_,
            permissions_attr=USER_SCHEMA.permissions_attr,
            roles_attr=USER_SCHEMA.roles_attr,
        )
    except PermissionDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    return MessageOut(ok=True)


@router.get("/superuser-only", response_model=MessageOut)
def superuser_only(user: User = Depends(get_current_user)) -> MessageOut:
    try:
        ensure_user_is_superuser(user, attr=USER_SCHEMA.is_superuser_attr)
    except PermissionDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    return MessageOut(ok=True)


@router.post("/token/decode", response_model=dict)
def token_decode(payload: TokenIn) -> dict:
    try:
        return decode_access_token(payload.token)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid token")


@router.post("/token/introspect", response_model=TokenOut)
def token_introspect(payload: TokenIn) -> TokenOut:
    return TokenOut(
        jti=get_token_jti(payload.token),
        exp=get_token_exp(payload.token),
    )


@router.post("/tokens/consume-once", response_model=dict)
def consume_once(payload: TokenIn, db: Session = Depends(get_db)) -> dict:
    subject = consume_one_time_token(
        payload.token,
        is_jti_used=lambda jti: is_jti_used(db, jti),
        mark_jti_used=lambda jti, exp: mark_jti_used(db, jti, exp),
        require_jti=True,
    )
    if subject is None:
        raise HTTPException(status_code=400, detail="Token invalid, expired, or already used")
    return {"subject": subject}


@router.post("/security-questions/set", response_model=MessageOut)
def set_security_answer(
    payload: SecurityQuestionSetIn,
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MessageOut:
    try:
        ensure_user_is_superuser(current, attr=USER_SCHEMA.is_superuser_attr)
    except PermissionDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    target = _get_user_by_email_or_404(db, str(payload.email))
    target.sec_answer_hash = payload.answer_hash
    db.add(target)
    db.commit()
    return MessageOut(ok=True)


@router.post("/security-questions/hash", response_model=SecurityAnswerHashOut)
def hash_security_answer_endpoint(payload: SecurityAnswerIn) -> SecurityAnswerHashOut:
    return SecurityAnswerHashOut(answer_hash=hash_security_answer(payload.answer))


@router.post("/security-questions/verify", response_model=MessageOut)
def verify_security_answer(
    username: str | None = None,
    email: str | None = None,
    answer: str = "",
    db: Session = Depends(get_db),
) -> MessageOut:
    user = verify_security_question_challenge(
        db=db,
        username=username,
        email=email,
        answer=answer,
        get_user_by_username=lambda db, u: get_user_by_username(db, u),
        get_user_by_email=lambda db, e: get_user_by_email(db, e),
        get_stored_answer_hash=lambda u: u.sec_answer_hash or None,
        ensure_active=True,
        user_schema=USER_SCHEMA,
    )
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid challenge")
    return MessageOut(ok=True)


@router.post("/origin/validate", response_model=dict)
def origin_check(payload: OriginCheckIn) -> dict:
    try:
        validated = validate_origin(payload.origin, payload.allowed_origins, allow_null_origin=payload.allow_null_origin)
    except OriginError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    return {"origin": validated}


@router.get("/security-headers", response_model=dict)
def security_headers() -> dict:
    return apply_security_headers(
        None,
        content_security_policy="default-src 'self'",
        hsts_max_age=31536000,
    )


@router.post("/echo-headers", response_model=dict)
def echo_headers(request: Request, x_demo: str | None = Header(default=None, alias="X-Demo")) -> dict:
    return {"x_demo": x_demo, "has_cookies": bool(request.cookies)}
