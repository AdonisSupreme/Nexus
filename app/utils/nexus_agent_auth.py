"""Agent credential checks for Sentinel Nexus ingestion endpoints."""

from __future__ import annotations

from hmac import compare_digest

from fastapi import HTTPException, Request, status

from app.config.settings import settings


def _extract_token(request: Request) -> str | None:
    header_token = request.headers.get("x-nexus-agent-token")
    if header_token:
        return header_token.strip()
    authorization = request.headers.get("authorization") or ""
    if authorization.startswith("Bearer "):
        return authorization.split(" ", 1)[1].strip()
    return None


def validate_nexus_agent_request(request: Request, *, agent_id: str, service_id: str) -> None:
    """Validate collector credentials and make sure the service is catalog allowlisted."""
    services = request.app.state.services
    if not any(service.service_id == service_id for service in services.nexus.list_services()):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Unknown Nexus service '{service_id}'.")

    header_agent_id = request.headers.get("x-nexus-agent-id")
    if header_agent_id and header_agent_id != agent_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Agent identifier mismatch.")

    if not settings.NEXUS_REQUIRE_AGENT_AUTH:
        return

    if not settings.NEXUS_AGENT_API_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Nexus agent authentication is required but NEXUS_AGENT_API_TOKEN is not configured.",
        )

    supplied_token = _extract_token(request)
    configured_token = settings.NEXUS_AGENT_API_TOKEN.get_secret_value()
    if not supplied_token or not compare_digest(supplied_token, configured_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Nexus agent credentials.")
