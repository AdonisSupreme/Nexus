"""Authentication helpers for protected operations."""

from __future__ import annotations

import secrets

from fastapi import Header, HTTPException, status

from app.config.settings import settings


def require_admin_token(x_admin_token: str | None = Header(default=None)) -> str:
    """Protect admin surfaces with a simple token gate."""
    configured = settings.ADMIN_API_TOKEN.get_secret_value() if settings.ADMIN_API_TOKEN else ""

    if not configured:
        if settings.is_production:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Admin token is not configured.",
            )
        return "development-bypass"

    if not x_admin_token or not secrets.compare_digest(x_admin_token, configured):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing admin token.",
        )

    return x_admin_token
