"""Read-only SMS queue evidence. No gateway calls, retries, or source mutations."""
from contextlib import contextmanager
from datetime import datetime, timezone
from threading import BoundedSemaphore, Lock
from time import monotonic
from zoneinfo import ZoneInfo

from app.config.settings import settings

STATES = ('QUEUED', 'RETRYABLE', 'ERROR', 'SEND')
BASE = "channel = 'SMS' AND deleted IS NOT TRUE"
_connections = BoundedSemaphore(3)
_overview_lock = Lock()
_overview_cache = None
_overview_until = 0
_source_revision = 0
_overview_revision = -1


def invalidate_sms_cache():
    global _source_revision, _overview_until
    _source_revision += 1
    _overview_until = 0


@contextmanager
def overview_guard():
    if not _overview_lock.acquire(timeout=1):
        raise RuntimeError('An SMS overview refresh is already in progress.')
    try:
        yield
    finally:
        _overview_lock.release()


def mask_recipient(value):
    value = str(value or '')
    return ('•' * min(8, max(0, len(value) - 4)) + value[-4:]) if value else 'Not supplied'


def scope_sql(status='', source='', search='', hours=0, aged=False, before=None):
    clauses, args = [BASE], []
    if status:
        if status not in STATES:
            raise ValueError('Unknown SMS status.')
        clauses.append('status = %s'); args.append(status)
    if source:
        clauses.append('source = %s'); args.append(source)
    if search:
        # Exact lookup avoids wildcard scans over customer message bodies.
        if search.isascii() and search.isdigit() and 0 < int(search) <= 9223372036854775807:
            clauses.append('(id = %s OR recipients = %s)'); args.extend([int(search), search])
        else:
            clauses.append('recipients = %s'); args.append(search)
    if hours:
        if hours not in (1, 24, 168):
            raise ValueError('Unsupported time window.')
        clauses.append("created_at >= LOCALTIMESTAMP - (%s * interval '1 hour')"); args.append(hours)
    if aged:
        clauses.append("status IN ('QUEUED','RETRYABLE') AND created_at < LOCALTIMESTAMP - interval '1 hour'")
    if before is not None:
        clauses.append('id < %s'); args.append(before)
    return ' AND '.join(clauses), args


class SmsMonitor:
    @property
    def configured(self):
        return bool(settings.SMSAL_HOST and settings.SMSAL_USERNAME and settings.SMSAL_PASSWORD)

    @contextmanager
    def connection(self):
        if not self.configured:
            raise ValueError('SMS monitoring is not configured. Set the server-side SMSAL connection settings.')
        ZoneInfo(settings.SMSAL_TIMEZONE)
        if not _connections.acquire(timeout=1):
            raise RuntimeError('SMS monitor is busy; retry shortly.')
        try:
            import psycopg
            from psycopg.rows import dict_row
            with psycopg.connect(host=settings.SMSAL_HOST, port=settings.SMSAL_PORT,
                    user=settings.SMSAL_USERNAME, password=settings.SMSAL_PASSWORD.get_secret_value(),
                    dbname=settings.SMSAL_DATABASE, sslmode=settings.SMSAL_SSLMODE,
                    connect_timeout=5, row_factory=dict_row,
                    options='-c default_transaction_read_only=on -c statement_timeout=8000 -c lock_timeout=1000') as conn:
                with conn.cursor() as cur:
                    cur.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
                    cur.execute("SELECT set_config('TimeZone', %s, true)", (settings.SMSAL_TIMEZONE,))
                    yield cur
        finally:
            _connections.release()

    def serialize(self, row):
        row = dict(row)
        for key, value in row.items():
            if isinstance(value, datetime):
                row[key] = value.replace(tzinfo=ZoneInfo(settings.SMSAL_TIMEZONE)).astimezone(timezone.utc).isoformat() if value.tzinfo is None else value.isoformat()
        if 'id' in row:
            row['id'] = str(row['id'])  # PostgreSQL bigint must not lose precision in JavaScript.
        return row

    def overview(self):
        global _overview_cache, _overview_until, _overview_revision
        if not self.configured:
            return {'configured': False, 'source_timezone': settings.SMSAL_TIMEZONE}
        with overview_guard():
            if _overview_cache is not None and _overview_revision == _source_revision and monotonic() < _overview_until:
                return _overview_cache
            revision = _source_revision
            with self.connection() as cur:
                cur.execute(f"""SELECT count(*) AS retained,
                    count(*) FILTER (WHERE status='QUEUED') AS queued,
                    count(*) FILTER (WHERE status='RETRYABLE') AS retryable,
                    count(*) FILTER (WHERE status='ERROR') AS errors,
                    count(*) FILTER (WHERE status='SEND') AS sent,
                    count(*) FILTER (WHERE status IS NULL OR status NOT IN ('QUEUED','RETRYABLE','ERROR','SEND')) AS unknown,
                    min(created_at) AS retained_since,
                    min(created_at) FILTER (WHERE status IN ('QUEUED','RETRYABLE')) AS oldest_waiting,
                    count(*) FILTER (WHERE status IN ('QUEUED','RETRYABLE') AND created_at < LOCALTIMESTAMP - interval '1 hour') AS aged,
                    count(*) FILTER (WHERE created_at >= LOCALTIMESTAMP - interval '15 minutes') AS arrivals_15m,
                    count(*) FILTER (WHERE status='SEND' AND updated_at >= LOCALTIMESTAMP - interval '15 minutes') AS sent_updated_15m,
                    count(*) FILTER (WHERE status IN ('QUEUED','RETRYABLE') AND created_at >= LOCALTIMESTAMP - interval '5 minutes') AS age_under_5m,
                    count(*) FILTER (WHERE status IN ('QUEUED','RETRYABLE') AND created_at < LOCALTIMESTAMP - interval '5 minutes' AND created_at >= LOCALTIMESTAMP - interval '1 hour') AS age_5m_1h,
                    count(*) FILTER (WHERE status IN ('QUEUED','RETRYABLE') AND created_at < LOCALTIMESTAMP - interval '1 hour' AND created_at >= LOCALTIMESTAMP - interval '24 hours') AS age_1h_24h,
                    count(*) FILTER (WHERE status IN ('QUEUED','RETRYABLE') AND created_at < LOCALTIMESTAMP - interval '24 hours') AS age_over_24h,
                    count(*) FILTER (WHERE status IN ('QUEUED','RETRYABLE') AND created_at IS NULL) AS age_unknown
                    FROM public.queue WHERE {BASE}""")
                result = self.serialize(cur.fetchone())
                cur.execute(f"""SELECT source, count(*) AS total,
                    count(*) FILTER (WHERE status IN ('QUEUED','RETRYABLE')) AS waiting,
                    count(*) FILTER (WHERE status='ERROR') AS errors
                    FROM public.queue WHERE {BASE} GROUP BY source
                    ORDER BY waiting DESC, errors DESC, total DESC, source NULLS LAST LIMIT 12""")
                result['sources'] = cur.fetchall()
                cur.execute(f"""SELECT date_trunc('hour',created_at) AS hour, count(*) AS arrivals,
                    count(*) FILTER (WHERE status='SEND') AS now_sent
                    FROM public.queue WHERE {BASE} AND created_at >= LOCALTIMESTAMP - interval '24 hours'
                    GROUP BY 1 ORDER BY 1""")
                result['activity'] = [self.serialize(row) for row in cur.fetchall()]
                result.update(configured=True, source_timezone=settings.SMSAL_TIMEZONE,
                    observed_at=datetime.now(timezone.utc).isoformat(), refresh_seconds=1)
            _overview_cache, _overview_until = result, monotonic() + 1
            _overview_revision = revision
            return result

    def records(self, **filters):
        where, args = scope_sql(**filters)
        with self.connection() as cur:
            cur.execute(f"""SELECT id, created_at, updated_at, status, recipients, source,
                retry_count, node, sender FROM public.queue WHERE {where} ORDER BY id DESC LIMIT 51""", args)
            rows = cur.fetchall()
        items = []
        for row in rows[:50]:
            row['recipients'] = mask_recipient(row['recipients'])
            items.append(self.serialize(row))
        return {'items': items, 'next_cursor': items[-1]['id'] if len(rows)>50 else None,
            'observed_at': datetime.now(timezone.utc).isoformat()}

    def detail(self, record_id):
        with self.connection() as cur:
            cur.execute(f"""SELECT id, created_at, updated_at, channel, status, recipients,
                message, sender, template, source, retry_count, response, node, queued_recipients
                FROM public.queue WHERE {BASE} AND id=%s""", (record_id,))
            row = cur.fetchone()
        if row is None:
            raise LookupError('This SMS record is no longer in the active queue. It may have been archived or removed by the source service.')
        return self.serialize(row)
