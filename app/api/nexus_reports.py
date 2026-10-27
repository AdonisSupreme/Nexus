"""SentinelOps reporting APIs backed by the Nexus runtime."""

from __future__ import annotations

from datetime import date, datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field, SecretStr
from starlette.concurrency import run_in_threadpool

from app.nexus.crb_reporting import CRBStorageError
from app.nexus.hovering_monitor import HoveringStorageError
from app.nexus.queue_recovery import QueueRecovery, HoveringRecoveryGateway
from app.nexus.personal_loans import PersonalLoanGateway
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


@router.get('/nexus/reports/personal-loans/overview')
async def personal_loan_overview(currency: str = '', _: dict = Depends(require_nexus_access)):
    try:
        return await run_in_threadpool(PersonalLoanGateway().overview, currency)
    except Exception as exc:
        logger.exception('Personal loan source read failed')
        raise HTTPException(503, 'Personal loan source unavailable. Check the server connection and permissions.') from exc


class PersonalReportScope(BaseModel):
    currency: str = Field(default='', pattern='^(USD|ZWL)?$')
    status: str = Field(default='', pattern='^(PENDING|SUCCESS|FAILED)?$')
    lookup: str = Field(default='', max_length=255)
    branch: str = Field(default='', max_length=100)
    description: str | None = Field(default=None, max_length=4000)
    date_basis: str = Field(default='created', pattern='^(created|processed)$')
    created_from: datetime | None = None
    created_to: datetime | None = None
    maturity_after: date | None = None
    maturity_to: date | None = None
    pay_from: date | None = None
    pay_to: date | None = None


@router.get('/nexus/reports/personal-loans/records')
async def personal_loan_records(scope: PersonalReportScope = Depends(), page: int = Query(1, ge=1),
    _: dict = Depends(require_nexus_access)):
    try:
        return await run_in_threadpool(PersonalLoanGateway().records, scope.model_dump(mode='json'), page)
    except ValueError as exc:
        raise _http_error(exc) from exc
    except Exception as exc:
        logger.exception('Personal loan records unavailable')
        raise HTTPException(503, 'Personal loan records unavailable. Check the server connection and permissions.') from exc


@router.get('/nexus/reports/personal-loans/report')
async def personal_report(scope: PersonalReportScope = Depends(), _: dict = Depends(require_nexus_access)):
    try:
        return await run_in_threadpool(PersonalLoanGateway().report, scope.model_dump(mode='json'))
    except ValueError as exc:
        raise _http_error(exc) from exc
    except Exception as exc:
        logger.exception('Personal loan report unavailable')
        raise HTTPException(503, 'Personal loan report unavailable. Check the source connection.') from exc


@router.get('/nexus/reports/personal-loans/export')
async def personal_export(scope: PersonalReportScope = Depends(), _: dict = Depends(require_nexus_access)):
    try:
        content = await run_in_threadpool(PersonalLoanGateway().export_csv, scope.model_dump(mode='json'))
        stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        return Response(content, media_type='text/csv', headers={
            'Content-Disposition': f'attachment; filename="personal-loans-{scope.currency or "both"}-{scope.status or "all"}-{stamp}.csv"',
            'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})
    except ValueError as exc:
        raise _http_error(exc) from exc
    except Exception as exc:
        logger.exception('Personal loan export unavailable')
        raise HTTPException(503, 'Report download unavailable. Check the source connection.') from exc


@router.get('/nexus/reports/personal-loans/failure-reasons')
async def personal_failure_reasons(currency: str = '', _: dict = Depends(require_nexus_access)):
    try:
        return await run_in_threadpool(PersonalLoanGateway().reasons, currency)
    except Exception as exc:
        raise HTTPException(503, 'Failure reasons unavailable.') from exc


@router.get('/nexus/reports/personal-loans/custody')
async def personal_custody(page: int = Query(1, ge=1), _: dict = Depends(require_nexus_admin)):
    try:
        result = await run_in_threadpool(QueueRecovery('personal-loans', PersonalLoanGateway()).history, page)
        return {'recoveries':result['items'], 'date_actions':[], 'policy_audit':[], 'has_more':result['has_more']}
    except Exception as exc:
        raise _http_error(exc) from exc


class QueueRecoveryInput(BaseModel):
    currency: str | None = Field(default=None, pattern="^(USD|ZWL)?$")
    record_ids: list[str] | None = Field(default=None, min_length=1, max_length=500)
    lookup: str | None = Field(default=None, max_length=255)
    description: str | None = Field(default=None, max_length=4000)
    created_from: datetime | None = None
    created_to: datetime | None = None


class PersonalRecoveryInput(QueueRecoveryInput):
    branch: str | None = Field(default=None, max_length=100)
    date_basis: str = Field(default='created', pattern='^(created|processed)$')
    maturity_after: date | None = None
    maturity_to: date | None = None
    pay_from: date | None = None
    pay_to: date | None = None


@router.post('/nexus/reports/personal-loans/recovery/prepare')
async def personal_prepare(payload: PersonalRecoveryInput, user: dict = Depends(require_nexus_access)):
    try:
        return await run_in_threadpool(QueueRecovery('personal-loans', PersonalLoanGateway()).prepare, payload.model_dump(mode='json'), _actor(user))
    except ValueError as exc:
        raise _http_error(exc) from exc
    except Exception as exc:
        logger.exception('Personal loan recovery preparation failed')
        raise HTTPException(503, 'Recovery preparation unavailable. Check source connectivity and the custody migration.') from exc


@router.post('/nexus/reports/personal-loans/recovery/{action_id}/execute')
async def personal_execute(action_id: str, user: dict = Depends(require_nexus_access)):
    try:
        return await run_in_threadpool(QueueRecovery('personal-loans', PersonalLoanGateway()).execute, action_id, _actor(user))
    except ValueError as exc:
        raise _http_error(exc) from exc
    except Exception as exc:
        raise HTTPException(503, 'Recovery outcome unavailable. Check custody before retrying.') from exc


@router.get('/nexus/reports/hovering/failure-reasons')
async def hovering_failure_reasons(_: dict = Depends(require_nexus_access)):
    try:
        return await run_in_threadpool(HoveringRecoveryGateway().reasons)
    except Exception as exc:
        raise _http_error(exc) from exc


@router.post('/nexus/reports/hovering/recovery/prepare')
async def hovering_recovery_prepare(payload: QueueRecoveryInput, user: dict = Depends(require_nexus_access)):
    try:
        return await run_in_threadpool(QueueRecovery().prepare, payload.model_dump(mode='json'), _actor(user))
    except Exception as exc:
        raise _http_error(exc) from exc


@router.post('/nexus/reports/hovering/recovery/{action_id}/execute')
async def hovering_recovery_execute(action_id: str, user: dict = Depends(require_nexus_access)):
    try:
        return await run_in_threadpool(QueueRecovery().execute, action_id, _actor(user))
    except Exception as exc:
        raise _http_error(exc) from exc


@router.get('/nexus/reports/hovering/custody')
async def hovering_custody(request: Request, page: int = Query(default=1, ge=1), _: dict = Depends(require_nexus_admin)):
    def read():
        repo = request.app.state.services.hovering_monitor.repository
        dates = repo.recent_actions(limit=26, offset=(page-1)*25)
        policies = repo.policy_audit(limit=26, offset=(page-1)*25)
        recovery = QueueRecovery().history(page)
        return {'date_actions': dates[:25], 'policy_audit': policies[:25], 'recoveries': recovery['items'], 'has_more': len(dates)>25 or len(policies)>25 or recovery['has_more']}
    try:
        return await run_in_threadpool(read)
    except Exception as exc:
        raise _http_error(exc) from exc


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
    user: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    try:
        result = await run_in_threadpool(request.app.state.services.hovering_monitor.overview)
        if not has_nexus_admin_role(user):
            result = {**result, "date_actions": [], "policy_audit": []}
        return result
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
    description: str | None = Query(default=None, max_length=4000),
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
            description=description,
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
