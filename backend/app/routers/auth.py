"""Auth routes: login / logout / session check."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.auth import (
    COOKIE_NAME,
    issue_session_token,
    require_session,
    verify_password,
)
from app.config import settings
from app.schemas import LoginRequest, LoginResponse

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, response: Response) -> LoginResponse:
    if not verify_password(body.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password"
        )
    token = issue_session_token()
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        max_age=settings.session_expire_minutes * 60,
    )
    return LoginResponse(ok=True)


@router.post("/logout")
def logout(response: Response) -> dict:
    response.delete_cookie(COOKIE_NAME)
    return {"ok": True}


@router.get("/me")
def me(_: str = Depends(require_session)) -> dict:
    return {"authenticated": True, "user": "admin"}
