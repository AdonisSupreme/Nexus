"""Health endpoints."""

from __future__ import annotations

import platform
import shutil
import time
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.config.settings import settings

try:
    import psutil
except ImportError:  # pragma: no cover - optional runtime dependency
    psutil = None


router = APIRouter()
_PROCESS_STARTED_AT = time.time()


def _system_info() -> dict[str, Any]:
    disk = shutil.disk_usage(str(settings.BASE_DIR))
    disk_percent = round((disk.used / disk.total) * 100, 2) if disk.total else None
    if psutil is None:
        return {
            "cpu_percent": None,
            "memory_percent": None,
            "memory_total_gb": None,
            "disk_percent": disk_percent,
            "disk_total_gb": round(disk.total / (1024**3), 2),
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "psutil_available": False,
        }

    memory = psutil.virtual_memory()
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.05),
        "memory_percent": memory.percent,
        "memory_total_gb": round(memory.total / (1024**3), 2),
        "disk_percent": disk_percent,
        "disk_total_gb": round(disk.total / (1024**3), 2),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "psutil_available": True,
    }


@router.get("/health")
async def health_check(request: Request) -> dict[str, Any]:
    services = request.app.state.services
    info = _system_info()
    warnings: list[str] = []
    if isinstance(info["cpu_percent"], (int, float)) and info["cpu_percent"] > 85:
        warnings.append("CPU usage is elevated.")
    if isinstance(info["memory_percent"], (int, float)) and info["memory_percent"] > 85:
        warnings.append("Memory usage is elevated.")
    if isinstance(info["disk_percent"], (int, float)) and info["disk_percent"] > 90:
        warnings.append("Disk usage is elevated.")
    nexus_schema = services.nexus.repository.schema_status()
    if not nexus_schema.get("schema_ready"):
        warnings.append("Sentinel Nexus database schema is not ready.")
    agent_token_status = services.nexus.get_agent_token_status()

    return {
        "status": "healthy" if not warnings else "degraded",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "application": {
            "name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT,
        },
        "engine": {
            "sops": len(services.indexer.normalized_sops),
            "chunks": len(services.indexer.chunks),
            "mistral_available": services.mistral_client.available,
        },
        "nexus": {
            **nexus_schema,
            "auth_mode": "sentinelops_session",
            "agent_auth_required": settings.NEXUS_REQUIRE_AGENT_AUTH,
            "agent_auth_configured": bool(agent_token_status.get("configured")),
            "agent_auth_source": agent_token_status.get("source"),
            "local_state_disabled": not nexus_schema.get("local_state_enabled", False),
            "osemn": {
                "obtain": "Evidence Intake",
                "scrub": "Normalization",
                "explore": "Correlation",
                "model": "Prediction",
                "interpret": "Operator Guidance",
            },
        },
        "system": info,
        "warnings": warnings,
    }


@router.get("/health/readiness", response_model=None)
async def readiness_check(request: Request) -> JSONResponse:
    services = request.app.state.services
    dependencies = {
        "knowledge_loaded": bool(services.indexer.normalized_sops),
        "retriever_ready": bool(services.retriever._doc_lengths),
        "audit_log_ready": settings.audit_file_path.parent.exists(),
        "raw_directories_present": all(directory.exists() for directory in settings.raw_knowledge_dirs),
        "nexus_database_ready": services.nexus.repository.schema_status().get("schema_ready", False),
    }
    ready = all(dependencies.values())
    payload = {
        "status": "ready" if ready else "not_ready",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "dependencies": dependencies,
    }
    status_code = 200 if ready else 503
    return JSONResponse(status_code=status_code, content=payload)


@router.get("/health/liveness")
async def liveness_check() -> dict[str, Any]:
    return {
        "status": "alive",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "uptime_seconds": round(time.time() - _PROCESS_STARTED_AT, 3),
    }
