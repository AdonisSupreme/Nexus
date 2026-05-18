"""SentinelOps session authentication for Nexus APIs."""

from __future__ import annotations

from typing import Any

from fastapi import Header, HTTPException, status
import jwt
import psycopg
from psycopg.rows import dict_row

from app.config.settings import settings
from app.utils.logging import get_logger


logger = get_logger(__name__)


def _database_dsn() -> str:
    dsn = settings.nexus_database_dsn
    if not dsn:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SentinelOps database is not configured for Nexus authentication.",
        )
    return dsn


def _secret_key() -> str:
    if not settings.SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SentinelOps SECRET_KEY is not configured for Nexus authentication.",
        )
    return settings.SECRET_KEY.get_secret_value()


def _decode_token(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(token, _secret_key(), algorithms=[settings.ALGORITHM])
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired.") from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token.") from exc


async def get_current_sentinelops_user(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """Validate the frontend Bearer token against SentinelOps auth_sessions."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid token.")

    payload = _decode_token(authorization.split(" ", 1)[1])
    user_id = payload.get("sub")
    session_id = payload.get("sid")
    if not user_id or not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token missing session claims.")

    query = """
    SELECT
        u.id::text AS id,
        u.username,
        u.email,
        u.first_name,
        u.last_name,
        u.created_at,
        r.name AS role,
        u.department_id,
        u.section_id::text AS section_id
    FROM auth_sessions s
    JOIN users u ON u.id = s.user_id
    JOIN user_roles ur ON ur.user_id = u.id
    JOIN roles r ON r.id = ur.role_id
    WHERE s.id = %s
      AND s.user_id = %s
      AND s.revoked_at IS NULL
      AND s.expires_at > (NOW() AT TIME ZONE 'UTC')
    LIMIT 1
    """
    try:
        with psycopg.connect(_database_dsn(), row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                row = cur.execute(query, (session_id, user_id)).fetchone()
    except Exception as exc:
        logger.exception("Nexus SentinelOps session validation failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SentinelOps session validation is unavailable.",
        ) from exc

    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session invalid or expired.")

    return dict(row)


def has_nexus_write_role(user: dict[str, Any]) -> bool:
    allowed = {role.lower() for role in settings.NEXUS_WRITE_ROLES}
    return str(user.get("role") or "").lower() in allowed


def has_nexus_admin_role(user: dict[str, Any]) -> bool:
    allowed = {role.lower() for role in settings.NEXUS_ADMIN_ROLES}
    return str(user.get("role") or "").lower() in allowed


def has_nexus_section_access(user: dict[str, Any]) -> bool:
    allowed = {section.lower() for section in settings.NEXUS_ALLOWED_SECTION_IDS}
    if not allowed:
        return True
    return str(user.get("section_id") or "").lower() in allowed


async def require_nexus_access(
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    user = await get_current_sentinelops_user(authorization)
    if not has_nexus_section_access(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sentinel Nexus is restricted to the authorized SentinelOps section.",
        )
    return user


async def require_nexus_operator(
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    user = await require_nexus_access(authorization)
    if not has_nexus_write_role(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your SentinelOps role does not allow this Nexus operation.",
        )
    return user


async def require_nexus_admin(
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    user = await require_nexus_access(authorization)
    if not has_nexus_admin_role(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only SentinelOps administrators can modify the Nexus catalog and control-plane configuration.",
        )
    return user
