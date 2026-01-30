from __future__ import annotations

import os

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response

from iam_utils.config import iam_config
from iam_utils.middleware import CSRFError, validate_csrf_request
from iam_utils.tokens import create_csrf_token

from .auth_routes import router as auth_router
from .db import init_db
from .demo_routes import router as demo_router
from .deps import get_current_user
from .schemas import MessageOut, UserOut


app = FastAPI(title="iam_utils demo")


@app.on_event("startup")
def _startup() -> None:
    init_db()
    iam_config.load_from_env()

    # For local demo convenience only.
    if os.getenv("IAM_SECRET_KEY") in (None, "", "change_me"):
        os.environ["IAM_SECRET_KEY"] = "dev-secret-change-me"
        iam_config.load_from_env()

    if os.getenv("IAM_PASSWORD_SCHEMES") in (None, ""):
        os.environ["IAM_PASSWORD_SCHEMES"] = "pbkdf2_sha256"
        iam_config.load_from_env()


app.include_router(auth_router)
app.include_router(demo_router)


@app.get("/me", response_model=UserOut, tags=["auth"])
def me(user=Depends(get_current_user)) -> UserOut:
    return UserOut(
        username=user.login_name,
        email=user.mail,
        is_active=user.active_flag,
        is_superuser=user.admin_flag,
        permissions=user.perms,
        roles=user.role_names,
    )


@app.get("/debug/csrf", response_model=dict, tags=["csrf"])
def issue_csrf_token(user=Depends(get_current_user)) -> dict:
    # In a real app you'd set this as a cookie (not HttpOnly) and have the frontend echo it
    # in X-CSRF-Token for unsafe methods. For simplicity we just return it.
    return {"csrf_token": create_csrf_token(subject=user.mail)}


@app.post("/debug/set-csrf-cookie", response_model=MessageOut, tags=["csrf"])
def set_csrf_cookie(response: Response, user=Depends(get_current_user)) -> MessageOut:
    token = create_csrf_token(subject=user.mail)
    response.set_cookie(
        "csrftoken",
        token,
        httponly=False,
        secure=False,
        samesite="lax",
        path="/",
    )
    return MessageOut(ok=True, detail=f"csrftoken cookie set (use X-CSRF-Token: {token})")


@app.post("/protected/change-email", response_model=MessageOut, tags=["csrf"])
def change_email(
    request: Request,
    x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    user=Depends(get_current_user),
) -> MessageOut:
    # Minimal example of double-submit CSRF check.
    try:
        validate_csrf_request(
            method=request.method,
            header_token=x_csrf_token,
            cookie_token=request.cookies.get("csrftoken"),
        )
    except CSRFError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    # Demo endpoint doesn't actually change anything.
    return MessageOut(ok=True, detail=f"CSRF validated for {user.mail}")
