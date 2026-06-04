"""Agent credential checks for Sentinel Nexus ingestion endpoints."""

from __future__ import annotations

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

    supplied_token = _extract_token(request)
    if services.nexus.validate_agent_token(supplied_token):
        return

    status_payload = services.nexus.get_agent_token_status()
    if not status_payload.get("configured") and not settings.NEXUS_AGENT_API_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Nexus agent authentication is required but no database-backed or environment token is configured.",
        )

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Nexus agent credentials.")
