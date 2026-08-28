"""SentinelOps reporting APIs backed by the Nexus runtime."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, SecretStr
from starlette.concurrency import run_in_threadpool

from app.nexus.crb_reporting import CRBStorageError
from app.nexus.hovering_monitor import HoveringStorageError
from app.utils.logging import get_logger
from app.utils.sentinelops_auth import (
    has_nexus_admin_role,
    require_hovering_password_editor,
    require_nexus_access,
    require_nexus_admin,
    require_nexus_operator,
)


logger = get_logger(__name__)
router = APIRouter()


def _actor(user: dict) -> str:
    return str(user.get("username") or user.get("email") or user.get("id") or "sentinel-operator")


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, LookupError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    if isinstance(exc, (CRBStorageError, HoveringStorageError)):
        return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    logger.exception("Reporting custody API operation failed")
    return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))


class HoveringDateResolveInput(BaseModel):
    record_ids: list[str] | None = Field(default=None, max_length=500)


class HoveringPolicyInput(BaseModel):
    enabled: bool


class HoveringRobotPasswordInput(BaseModel):
    password: SecretStr = Field(min_length=1, max_length=255)


class HoveringConfigurationInput(BaseModel):
    value: str = Field(max_length=255)


@router.get("/nexus/reports/crb/overview")
async def crb_overview(
    request: Request,
    _: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(request.app.state.services.crb_reports.overview)
    except Exception as exc:
        raise _http_error(exc) from exc


@router.post("/nexus/reports/crb/extractions", status_code=status.HTTP_202_ACCEPTED)
async def start_crb_extraction(
    request: Request,
    background_tasks: BackgroundTasks,
    user: dict = Depends(require_nexus_operator),
) -> dict[str, object]:
    try:
        run = await run_in_threadpool(
            request.app.state.services.crb_reports.prepare_run,
            trigger="MANUAL",
            requested_by=_actor(user),
        )
        background_tasks.add_task(
            request.app.state.services.crb_reports.execute_run,
            run["run_id"],
        )
        return run
    except Exception as exc:
        raise _http_error(exc) from exc


@router.get("/nexus/reports/crb/runs/{run_id}")
async def get_crb_run(
    run_id: str,
    request: Request,
    _: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(request.app.state.services.crb_reports.repository.get_run, run_id)
    except Exception as exc:
        raise _http_error(exc) from exc


@router.get("/nexus/reports/crb/artifacts/{artifact_id}/download")
async def download_crb_artifact(
    artifact_id: str,
    request: Request,
    _: dict = Depends(require_nexus_access),
) -> FileResponse:
    try:
        path, artifact = await run_in_threadpool(
            request.app.state.services.crb_reports.artifact_path,
            artifact_id,
        )
        return FileResponse(
            path,
            media_type="text/csv",
            filename=str(artifact["filename"]),
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.get("/nexus/reports/hovering/overview")
async def hovering_overview(
    request: Request,
    _: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(request.app.state.services.hovering_monitor.overview)
    except Exception as exc:
        raise _http_error(exc) from exc


@router.get("/nexus/reports/hovering/records")
async def hovering_records(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    status_filter: str | None = Query(default="PENDING", alias="status", max_length=50),
    lookup: str | None = Query(default=None, max_length=255),
    created_from: datetime | None = Query(default=None),
    created_to: datetime | None = Query(default=None),
    _: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.hovering_monitor.records,
            page=page,
            page_size=page_size,
            status_filter=status_filter or None,
            lookup=lookup or None,
            created_from=created_from,
            created_to=created_to,
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.post("/nexus/reports/hovering/dates/resolve")
async def resolve_hovering_dates(
    payload: HoveringDateResolveInput,
    request: Request,
    user: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.hovering_monitor.resolve_dates,
            actor=_actor(user),
            trigger="MANUAL",
            record_ids=payload.record_ids,
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.put("/nexus/reports/hovering/policy")
async def update_hovering_policy(
    payload: HoveringPolicyInput,
    request: Request,
    user: dict = Depends(require_nexus_admin),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.hovering_monitor.set_policy,
            enabled=payload.enabled,
            actor=_actor(user),
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.get("/nexus/reports/hovering/settings")
async def hovering_settings(
    request: Request,
    user: dict = Depends(require_hovering_password_editor),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.hovering_monitor.settings_overview,
            include_configurations=has_nexus_admin_role(user),
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.put("/nexus/reports/hovering/settings/robots/{key}/password")
async def rotate_hovering_robot_password(
    key: str,
    payload: HoveringRobotPasswordInput,
    request: Request,
    user: dict = Depends(require_hovering_password_editor),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.hovering_monitor.rotate_robot_password,
            key=key,
            password=payload.password.get_secret_value(),
            actor=_actor(user),
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.put("/nexus/reports/hovering/settings/configurations/{key}")
async def update_hovering_configuration(
    key: str,
    payload: HoveringConfigurationInput,
    request: Request,
    user: dict = Depends(require_nexus_admin),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.hovering_monitor.update_general_configuration,
            key=key,
            value=payload.value,
            actor=_actor(user),
        )
    except Exception as exc:
        raise _http_error(exc) from exc
