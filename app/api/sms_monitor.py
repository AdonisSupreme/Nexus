"""Authenticated, module-scoped read endpoints for SMS monitoring."""
import logging
import asyncio
import json
from time import monotonic
from fastapi import APIRouter, Depends, HTTPException, Query, Response, Request
from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool
from app.nexus.sms_monitor import SmsMonitor
from app.utils.sentinelops_auth import require_nexus_access
from app.nexus.sms_events import sms_events

def private_evidence(response: Response):
    response.headers['Cache-Control'] = 'no-store'


router = APIRouter(prefix='/nexus/reports/sms', dependencies=[Depends(require_nexus_access), Depends(private_evidence)])
log = logging.getLogger(__name__)


async def read(operation, **kwargs):
    try:
        return await run_in_threadpool(operation, **kwargs)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        log.warning('SMS source read failed (%s)', type(exc).__name__)
        raise HTTPException(503, 'SMS source is temporarily unavailable. Last successful evidence is retained; retry shortly.') from exc


@router.get('/overview')
async def overview():
    return await read(SmsMonitor().overview)


@router.get('/events')
async def events(request: Request):
    async def stream():
        sms_events.subscribe()
        previous = None
        started = heartbeat = monotonic()
        try:
            # Short-lived stream reconnects through normal auth/module middleware,
            # so token expiry and section changes are enforced at most 20s later.
            while monotonic() - started < 20 and not await request.is_disconnected():
                state = sms_events.snapshot()
                if state != previous:
                    yield 'data: ' + json.dumps(state) + '\n\n'
                    previous = state
                    heartbeat = monotonic()
                elif monotonic() - heartbeat >= 5:
                    yield ': heartbeat\n\n'
                    heartbeat = monotonic()
                await asyncio.sleep(0.1)
        finally:
            sms_events.unsubscribe()
    return StreamingResponse(stream(), media_type='text/event-stream', headers={
        'Cache-Control':'no-store', 'X-Accel-Buffering':'no',
    })


@router.get('/records')
async def records(status: str = '', source: str = Query('', max_length=200),
                  search: str = Query('', max_length=200), hours: int = Query(0, ge=0, le=168),
                  aged: bool = False, before: int | None = Query(None, ge=1, le=9223372036854775807)):
    return await read(SmsMonitor().records, status=status, source=source, search=search.strip(), hours=hours, aged=aged, before=before)


@router.get('/records/{record_id}')
async def detail(record_id: int):
    if not 0 < record_id <= 9223372036854775807:
        raise HTTPException(400, 'Invalid SMS record ID.')
    return await read(SmsMonitor().detail, record_id=record_id)
