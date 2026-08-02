"""Single-user auth: one admin password, signed session cookie.

No users table by design (Module 1 is single-user). A successful login mints a
timed, signed token stored in an httponly cookie; every protected route verifies it.
"""
from __future__ import annotations

import hmac

from fastapi import Cookie, HTTPException, status
from itsdangerous import BadSignature, SignatureExpired, TimestampSigner
from itsdangerous import URLSafeTimedSerializer

from app.config import settings

COOKIE_NAME = "recongrid_session"
_serializer = URLSafeTimedSerializer(settings.secret_key, salt="recongrid-session")


def verify_password(candidate: str) -> bool:
    """Constant-time comparison against the configured admin password."""
    return hmac.compare_digest(candidate, settings.admin_password)


def issue_session_token() -> str:
    return _serializer.dumps({"sub": "admin"})


def validate_session_token(token: str) -> bool:
    max_age = settings.session_expire_minutes * 60
    try:
        _serializer.loads(token, max_age=max_age)
        return True
    except (BadSignature, SignatureExpired):
        return False


def require_session(
    recongrid_session: str | None = Cookie(default=None),
) -> str:
    """FastAPI dependency guarding protected routes."""
    if not recongrid_session or not validate_session_token(recongrid_session):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return "admin"
