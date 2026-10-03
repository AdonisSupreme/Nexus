"""Sentinel Nexus unauthorized clearing API."""

from __future__ import annotations

import json

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from starlette.concurrency import run_in_threadpool

from app.nexus.unauthorized_clearing import (
    ClearingApprovalRequest,
    ClearingAccountBatchRequest,
    ClearingBatchCreateRequest,
    ClearingBulkSelectionRequest,
    ClearingExecutionRequest,
    ClearingPolicyUpdateRequest,
    ClearingRollbackRequest,
    ClearingSelectionRequest,
    ClearingSourceImportRequest,
    ClearingStorageError,
    ClearingSubmitRequest,
)
from app.utils.logging import get_logger
from app.utils.sentinelops_auth import (
    get_current_sentinelops_user,
    require_nexus_access,
    require_nexus_admin,
    require_nexus_clearing_approver,
    require_nexus_clearing_executor,
    require_nexus_clearing_maker,
    require_nexus_clearing_rollback,
)


logger = get_logger(__name__)
router = APIRouter()


def _actor(user: dict) -> str:
    return str(user.get("username") or user.get("email") or user.get("id") or "sentinel-operator")


def _role(user: dict) -> str:
    return str(user.get("role") or "unknown")


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, LookupError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    if isinstance(exc, ClearingStorageError):
        return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    logger.exception("Unauthorized clearing API operation failed")
    return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))


@router.get("/nexus/clearing/overview")
async def clearing_overview(
    request: Request,
    user: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.clearing.overview,
            actor_role=_role(user),
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.get("/nexus/clearing/policy/specific-record")
async def get_specific_record_clearing_policy(
    request: Request,
    user: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.clearing.specific_record_policy,
            actor_role=_role(user),
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.patch("/nexus/clearing/policy/specific-record")
async def update_specific_record_clearing_policy(
    request_body: ClearingPolicyUpdateRequest,
    request: Request,
    user: dict = Depends(require_nexus_admin),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.clearing.set_specific_record_policy,
            request_body,
            actor=_actor(user),
            actor_role=_role(user),
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.get("/nexus/clearing/batches")
async def list_clearing_batches(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    _: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    try:
        batches = await run_in_threadpool(request.app.state.services.clearing.repository.list_batches, limit)
        return {"batches": batches}
    except Exception as exc:
        raise _http_error(exc) from exc


@router.post("/nexus/clearing/batches", status_code=status.HTTP_201_CREATED)
async def create_clearing_batch(
    request_body: ClearingBatchCreateRequest,
    request: Request,
    user: dict = Depends(require_nexus_clearing_maker),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.clearing.create_batch,
            request_body,
            actor=_actor(user),
            actor_role=_role(user),
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.post("/nexus/clearing/batches/import", status_code=status.HTTP_201_CREATED)
async def import_clearing_batch(
    request_body: ClearingSourceImportRequest,
    request: Request,
    user: dict = Depends(require_nexus_clearing_maker),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.clearing.import_source,
            request_body,
            actor=_actor(user),
            actor_role=_role(user),
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.get("/nexus/clearing/batches/{batch_id}")
async def get_clearing_batch(
    batch_id: str,
    request: Request,
    _: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(request.app.state.services.clearing.repository.get_batch, batch_id)
    except Exception as exc:
        raise _http_error(exc) from exc


@router.delete("/nexus/clearing/batches/{batch_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_clearing_batch(
    batch_id: str,
    request: Request,
    user: dict = Depends(require_nexus_clearing_maker),
) -> None:
    try:
        await run_in_threadpool(
            request.app.state.services.clearing.repository.delete_batch,
            batch_id,
            actor=_actor(user),
            actor_role=_role(user),
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.patch("/nexus/clearing/batches/{batch_id}/transactions/{fingerprint}")
async def select_clearing_transaction(
    batch_id: str,
    fingerprint: str,
    request_body: ClearingSelectionRequest,
    request: Request,
    user: dict = Depends(require_nexus_clearing_maker),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.clearing.repository.set_selection,
            batch_id,
            fingerprint,
            request_body.selected,
            actor=_actor(user),
            actor_role=_role(user),
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.put("/nexus/clearing/batches/{batch_id}/selection")
async def set_clearing_batch_selection(
    batch_id: str,
    request_body: ClearingBulkSelectionRequest,
    request: Request,
    user: dict = Depends(require_nexus_clearing_maker),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.clearing.repository.set_bulk_selection,
            batch_id,
            request_body.action,
            actor=_actor(user),
            actor_role=_role(user),
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.post("/nexus/clearing/batches/{batch_id}/reconcile")
async def reconcile_clearing_batch(
    batch_id: str,
    request: Request,
    user: dict = Depends(require_nexus_clearing_maker),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.clearing.reconcile,
            batch_id,
            actor=_actor(user),
            actor_role=_role(user),
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.post("/nexus/clearing/batches/{batch_id}/submit")
async def submit_clearing_batch(
    batch_id: str,
    request_body: ClearingSubmitRequest,
    request: Request,
    user: dict = Depends(require_nexus_clearing_maker),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.clearing.submit,
            batch_id,
            request_body,
            actor=_actor(user),
            actor_role=_role(user),
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.post("/nexus/clearing/batches/{batch_id}/approval")
async def approve_clearing_batch(
    batch_id: str,
    request_body: ClearingApprovalRequest,
    request: Request,
    user: dict = Depends(require_nexus_clearing_approver),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.clearing.approve,
            batch_id,
            request_body,
            actor=_actor(user),
            actor_role=_role(user),
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.get("/nexus/clearing/batches/{batch_id}/execution-preview")
async def clearing_execution_preview(
    batch_id: str,
    request: Request,
    _: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(request.app.state.services.clearing.execution_preview, batch_id)
    except Exception as exc:
        raise _http_error(exc) from exc


@router.post("/nexus/clearing/batches/{batch_id}/execute")
async def execute_clearing_batch(
    batch_id: str,
    request_body: ClearingExecutionRequest,
    request: Request,
    user: dict = Depends(require_nexus_clearing_executor),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.clearing.execute,
            batch_id,
            request_body,
            actor=_actor(user),
            actor_role=_role(user),
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.get("/nexus/clearing/executions")
async def list_clearing_executions(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    _: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    try:
        executions = await run_in_threadpool(
            request.app.state.services.clearing.repository.list_executions,
            limit,
        )
        return {"executions": executions}
    except Exception as exc:
        raise _http_error(exc) from exc


@router.get("/nexus/clearing/executions/{execution_id}")
async def get_clearing_execution(
    execution_id: str,
    request: Request,
    _: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.clearing.repository.get_execution,
            execution_id,
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.post("/nexus/clearing/executions/{execution_id}/rollback")
async def rollback_clearing_execution(
    execution_id: str,
    request_body: ClearingRollbackRequest,
    request: Request,
    user: dict = Depends(require_nexus_clearing_rollback),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.clearing.rollback,
            execution_id,
            request_body,
            actor=_actor(user),
            actor_role=_role(user),
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.get("/nexus/clearing/batches/{batch_id}/accounts/{external_account}")
async def get_clearing_account(
    batch_id: str,
    external_account: str,
    request: Request,
    _: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.clearing.account_view,
            batch_id,
            external_account,
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.get("/nexus/clearing/accounts/{external_account}")
async def inspect_live_clearing_account(
    external_account: str,
    request: Request,
    user: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.clearing.live_account_view,
            external_account,
            actor=_actor(user),
            actor_role=_role(user),
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.get("/nexus/clearing/rrns/{rrn}")
async def inspect_live_clearing_rrn(
    rrn: str,
    request: Request,
    user: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.clearing.live_rrn_view,
            rrn,
            actor=_actor(user),
            actor_role=_role(user),
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.post("/nexus/clearing/accounts/{external_account}/batches", status_code=status.HTTP_201_CREATED)
async def create_account_clearing_batch(
    external_account: str,
    request_body: ClearingAccountBatchRequest,
    request: Request,
    user: dict = Depends(require_nexus_clearing_maker),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.clearing.create_account_batch,
            external_account,
            request_body,
            actor=_actor(user),
            actor_role=_role(user),
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.post("/nexus/clearing/rrns/{rrn}/batches", status_code=status.HTTP_201_CREATED)
async def create_rrn_clearing_batch(
    rrn: str,
    request_body: ClearingAccountBatchRequest,
    request: Request,
    user: dict = Depends(require_nexus_clearing_maker),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.clearing.create_rrn_batch,
            rrn,
            request_body,
            actor=_actor(user),
            actor_role=_role(user),
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@router.get("/nexus/clearing/audit")
async def list_clearing_audit(
    request: Request,
    batch_id: str | None = Query(default=None),
    search: str | None = Query(default=None, max_length=128),
    limit: int = Query(default=150, ge=1, le=500),
    _: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    try:
        events = await run_in_threadpool(
            request.app.state.services.clearing.repository.list_audit,
            batch_id,
            limit,
            search,
        )
        return {"events": events}
    except Exception as exc:
        raise _http_error(exc) from exc


@router.websocket("/nexus/clearing/ws")
async def clearing_realtime(websocket: WebSocket, token: str = Query(...)) -> None:
    try:
        user = await get_current_sentinelops_user(f"Bearer {token}")
        # The shared middleware enforces funds_custody.workspace for this stream.
    except HTTPException:
        await websocket.close(code=4401, reason="Authentication failed")
        return

    dsn = websocket.app.state.services.clearing.repository.database_dsn
    if not dsn:
        await websocket.close(code=1011, reason="Funds Custody storage unavailable")
        return

    await websocket.accept()
    await websocket.send_json({"type": "CONNECTION_ESTABLISHED", "workspace": "funds-custody"})
    try:
        async with await psycopg.AsyncConnection.connect(dsn, autocommit=True) as connection:
            await connection.execute("LISTEN nexus_clearing_events")
            async for notification in connection.notifies():
                try:
                    payload = json.loads(notification.payload)
                except (TypeError, json.JSONDecodeError):
                    payload = {"type": "CUSTODY_UPDATE", "event_type": "unknown"}
                await websocket.send_json(payload)
    except WebSocketDisconnect:
        return
    except Exception:
        logger.exception("Funds Custody realtime stream failed")
        try:
            await websocket.close(code=1011, reason="Realtime stream unavailable")
        except RuntimeError:
            pass


@router.get("/nexus/clearing/audit/{audit_id}/evidence")
async def get_clearing_audit_evidence(
    audit_id: str,
    request: Request,
    _: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    try:
        return await run_in_threadpool(
            request.app.state.services.clearing.repository.get_audit_evidence,
            audit_id,
        )
    except Exception as exc:
        raise _http_error(exc) from exc
