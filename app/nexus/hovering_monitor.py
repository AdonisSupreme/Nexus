"""Loan hovering queue monitoring and guarded installment-date custody."""

from __future__ import annotations

import asyncio
import logging
import re
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Iterator, Literal
from uuid import uuid4
from zoneinfo import ZoneInfo

import httpx
import psycopg
from psycopg.rows import dict_row

from app.config.settings import settings
from app.utils.audit import audit_logger


logger = logging.getLogger(__name__)

HOVERING_MIGRATION = "2026_15_add_nexus_hovering_monitor.sql"
HOVERING_FLOW_MIGRATION = "2026_17_refine_nexus_hovering_flow.sql"
HOVERING_POLICY_KEY = "midnight-installment-rollover"
HOVERING_STATUSES = ("PENDING", "AWAITING_AUTHORIZATION", "FAILED", "AUTHORIZED")
ROBOT_SETTING_PATTERN = re.compile(r"^ROBHOV\d+$", re.IGNORECASE)


class HoveringStorageError(RuntimeError):
    """Raised when the SentinelOps custody schema is unavailable."""


class RobotPasswordEncryptor:
    """Transient handoff to the approved core-system password encryptor."""

    def __init__(
        self,
        url: str | None = None,
        timeout_seconds: float | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.url = (url if url is not None else settings.NEXUS_HOVERING_ENCRYPTION_URL).strip()
        self.timeout_seconds = (
            timeout_seconds
            if timeout_seconds is not None
            else settings.NEXUS_HOVERING_ENCRYPTION_TIMEOUT_SECONDS
        )
        self.transport = transport

    @property
    def configured(self) -> bool:
        return bool(self.url)

    def encrypt(self, password: str) -> str:
        if not self.url:
            raise RuntimeError("The hovering robot encryption service is not configured.")
        try:
            with httpx.Client(
                timeout=self.timeout_seconds,
                follow_redirects=False,
                transport=self.transport,
            ) as client:
                response = client.post(self.url, json={"password": password})
        except httpx.HTTPError as exc:
            raise RuntimeError("The hovering robot encryption service is unavailable.") from exc
        if not response.is_success:
            raise RuntimeError(
                f"The hovering robot encryption service returned HTTP {response.status_code}."
            )
        encrypted = response.text.strip()
        if encrypted.startswith('"') and encrypted.endswith('"'):
            encrypted = encrypted[1:-1]
        if not encrypted or len(encrypted) > 255 or any(character.isspace() for character in encrypted):
            raise RuntimeError("The hovering robot encryption service returned an invalid value.")
        return encrypted


def _parse_clock(value: str, setting_name: str) -> time:
    try:
        hour, minute = (int(part) for part in value.split(":", 1))
        return time(hour, minute)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"{setting_name} must use HH:MM 24-hour format.") from exc


def active_seconds_between(
    started_at: datetime,
    ended_at: datetime,
    *,
    zone: ZoneInfo,
    window_start: time,
    window_end: time,
    weekend_window_end: time | None = None,
) -> float:
    """Return seconds that fall inside the bot operating window."""
    start = started_at.astimezone(zone)
    end = ended_at.astimezone(zone)
    if end <= start:
        return 0.0
    total = 0.0
    day = start.date()
    while day <= end.date():
        lower = datetime.combine(day, window_start, tzinfo=zone)
        daily_end = weekend_window_end if weekend_window_end and day.weekday() >= 5 else window_end
        upper = datetime.combine(day, daily_end, tzinfo=zone)
        overlap_start = max(start, lower)
        overlap_end = min(end, upper)
        if overlap_end > overlap_start:
            total += (overlap_end - overlap_start).total_seconds()
        day += timedelta(days=1)
    return total


@dataclass(frozen=True)
class HoveringMovement:
    posture: Literal["CLEAR", "MOVING", "STALLED", "OBSERVING", "PAUSED"]
    rate_per_hour: float
    arrival_rate_per_hour: float
    net_rate_per_hour: float
    processed_count: int
    arrived_count: int
    net_change: int
    last_movement_at: datetime | None
    observed_active_minutes: float


def derive_movement(
    samples: list[dict[str, Any]],
    *,
    pending_count: int,
    created_count: int,
    now: datetime,
    zone: ZoneInfo,
    window_start: time,
    window_end: time,
    weekend_window_end: time,
    stall_minutes: int,
) -> HoveringMovement:
    ordered = sorted(
        (
            sample
            for sample in samples
            if sample.get("observed_at") is not None
            and sample.get("pending_count") is not None
            and sample.get("created_count") is not None
        ),
        key=lambda sample: sample["observed_at"],
    )
    local_now = now.astimezone(zone)
    active_window_started = datetime.combine(local_now.date(), window_start, tzinfo=zone)
    ordered = [sample for sample in ordered if sample["observed_at"].astimezone(zone) >= active_window_started]
    current = {
        "observed_at": now,
        "pending_count": pending_count,
        "created_count": created_count,
    }
    if not ordered or ordered[-1]["observed_at"] < now:
        ordered.append(current)

    daily_window_end = weekend_window_end if local_now.weekday() >= 5 else window_end
    window_open = window_start <= local_now.time().replace(tzinfo=None) < daily_window_end
    if pending_count <= 0:
        return HoveringMovement("CLEAR", 0.0, 0.0, 0.0, 0, 0, 0, None, 0.0)
    if not window_open:
        return HoveringMovement("PAUSED", 0.0, 0.0, 0.0, 0, 0, 0, None, 0.0)
    if len(ordered) < 2:
        return HoveringMovement("OBSERVING", 0.0, 0.0, 0.0, 0, 0, 0, None, 0.0)

    baseline = ordered[0]
    active_seconds = active_seconds_between(
        baseline["observed_at"],
        now,
        zone=zone,
        window_start=window_start,
        window_end=window_end,
        weekend_window_end=weekend_window_end,
    )
    baseline_pending = int(baseline["pending_count"])
    arrived_count = max(0, created_count - int(baseline["created_count"]))
    processed_count = max(0, baseline_pending + arrived_count - pending_count)
    net_change = pending_count - baseline_pending
    rate = (processed_count / active_seconds * 3600) if active_seconds > 0 else 0.0
    arrival_rate = (arrived_count / active_seconds * 3600) if active_seconds > 0 else 0.0
    net_rate = ((baseline_pending - pending_count) / active_seconds * 3600) if active_seconds > 0 else 0.0
    last_movement_at = None
    for previous, current_sample in zip(ordered, ordered[1:]):
        interval_arrivals = max(0, int(current_sample["created_count"]) - int(previous["created_count"]))
        interval_processed = max(
            0,
            int(previous["pending_count"]) + interval_arrivals - int(current_sample["pending_count"]),
        )
        if interval_processed > 0:
            last_movement_at = current_sample["observed_at"]

    active_minutes = active_seconds / 60
    movement_baseline = last_movement_at or baseline["observed_at"]
    inactive_active_minutes = active_seconds_between(
        movement_baseline,
        now,
        zone=zone,
        window_start=window_start,
        window_end=window_end,
        weekend_window_end=weekend_window_end,
    ) / 60
    if inactive_active_minutes >= max(1, stall_minutes):
        posture = "STALLED"
    elif rate > 0:
        posture = "MOVING"
    else:
        posture = "OBSERVING"
    return HoveringMovement(
        posture,
        round(rate, 2),
        round(arrival_rate, 2),
        round(net_rate, 2),
        processed_count,
        arrived_count,
        net_change,
        last_movement_at,
        round(active_minutes, 1),
    )


class HoveringQueueGateway:
    """Parameterized access to the txn-bot hovering table."""

    def __init__(self, dsn: str | None = None) -> None:
        self._dsn = dsn if dsn is not None else settings.txn_bot_database_dsn

    @property
    def configured(self) -> bool:
        return bool(self._dsn)

    @contextmanager
    def connection(self) -> Iterator[Any]:
        if not self._dsn:
            raise RuntimeError("txn-bot PostgreSQL is not configured. Set TXN_BOT_DATABASE_URL.")
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            yield connection

    def counts(self, *, business_day: date) -> dict[str, Any]:
        with self.connection() as connection:
            with connection.cursor() as cursor:
                row = cursor.execute(
                    """
                    SELECT
                        COUNT(*)::bigint AS created_count,
                        COUNT(*) FILTER (WHERE status = 'PENDING')::bigint AS pending_count,
                        COUNT(*) FILTER (
                            WHERE status = 'PENDING' AND installment_date::date < %s
                        )::bigint AS overdue_count,
                        COUNT(*) FILTER (
                            WHERE status = 'PENDING' AND installment_date::date = %s
                        )::bigint AS due_today_count,
                        COUNT(*) FILTER (
                            WHERE status = 'PENDING' AND installment_date::date > %s
                        )::bigint AS future_count,
                        MAX(updated) FILTER (WHERE status = 'PENDING') AS latest_queue_update,
                        MAX(created) AS latest_created_at,
                        MIN(created) FILTER (WHERE status = 'PENDING') AS oldest_pending_created
                    FROM hovering
                    WHERE credit_account = %s
                      AND type = %s
                    """,
                    (
                        business_day,
                        business_day,
                        business_day,
                        settings.NEXUS_HOVERING_CREDIT_ACCOUNT,
                        settings.NEXUS_HOVERING_TYPE,
                    ),
                ).fetchone()
        return dict(row or {})

    def records(
        self,
        *,
        page: int,
        page_size: int,
        status_filter: str | None,
        lookup: str | None,
        created_from: datetime | None,
        created_to: datetime | None,
    ) -> dict[str, Any]:
        clauses = ["credit_account = %s", "type = %s"]
        params: list[Any] = [settings.NEXUS_HOVERING_CREDIT_ACCOUNT, settings.NEXUS_HOVERING_TYPE]
        if status_filter:
            normalized_status = status_filter.upper()
            if normalized_status not in HOVERING_STATUSES:
                raise ValueError("Unknown hovering queue status.")
            clauses.append("status = %s")
            params.append(normalized_status)
        if lookup:
            clauses.append(
                "(debit_account ILIKE %s OR reference ILIKE %s OR external_reference ILIKE %s OR id = %s)"
            )
            pattern = f"%{lookup.strip()}%"
            params.extend([pattern, pattern, pattern, lookup.strip()])
        if created_from:
            clauses.append("created >= %s")
            params.append(created_from)
        if created_to:
            clauses.append("created < %s")
            params.append(created_to)
        where = " AND ".join(clauses)
        safe_page = max(1, page)
        safe_size = max(1, min(page_size, settings.NEXUS_HOVERING_MAX_PAGE_SIZE))
        offset = (safe_page - 1) * safe_size

        with self.connection() as connection:
            with connection.cursor() as cursor:
                total = int(
                    cursor.execute(f"SELECT COUNT(*) FROM hovering WHERE {where}", tuple(params)).fetchone()["count"]
                )
                rows = cursor.execute(
                    f"""
                    SELECT id, amount, beneficiary, credit_account, currency, debit_account,
                           description, reference, status, type, external_reference, created,
                           branch, extended_type, updated, installment_date
                    FROM hovering
                    WHERE {where}
                    ORDER BY created DESC NULLS LAST, id DESC
                    LIMIT %s OFFSET %s
                    """,
                    (*params, safe_size, offset),
                ).fetchall()
        return {
            "items": [dict(row) for row in rows],
            "page": safe_page,
            "page_size": safe_size,
            "total": total,
            "pages": max(1, (total + safe_size - 1) // safe_size),
        }

    def settings(self) -> dict[str, list[dict[str, Any]]]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT id, created, updated, key, value
                FROM setting
                WHERE deleted IS NULL
                ORDER BY CASE WHEN key ~* '^ROBHOV[0-9]+$' THEN 0 ELSE 1 END, key
                """
            ).fetchall()
        robots: list[dict[str, Any]] = []
        configurations: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            if ROBOT_SETTING_PATTERN.fullmatch(str(item.get("key") or "")):
                robots.append(
                    {
                        "id": item.get("id"),
                        "key": item.get("key"),
                        "created": item.get("created"),
                        "updated": item.get("updated"),
                        "credential_configured": bool(item.get("value")),
                    }
                )
            else:
                configurations.append(item)
        return {"robots": robots, "configurations": configurations}

    def update_robot_credential(self, *, key: str, encrypted_value: str) -> dict[str, Any]:
        normalized_key = key.strip().upper()
        if not ROBOT_SETTING_PATTERN.fullmatch(normalized_key):
            raise ValueError("Only ROBHOV robot credentials can use the password rotation path.")
        with self.connection() as connection:
            row = connection.execute(
                """
                UPDATE setting
                SET value = %s,
                    updated = now()
                WHERE key = %s
                  AND deleted IS NULL
                RETURNING id, key, created, updated
                """,
                (encrypted_value, normalized_key),
            ).fetchone()
            connection.commit()
        if not row:
            raise LookupError(f"Hovering robot {normalized_key} does not exist.")
        return {**dict(row), "credential_configured": True}

    def update_configuration(self, *, key: str, value: str) -> dict[str, Any]:
        normalized_key = key.strip().upper()
        if ROBOT_SETTING_PATTERN.fullmatch(normalized_key):
            raise ValueError("Robot credentials must use the protected password rotation path.")
        with self.connection() as connection:
            row = connection.execute(
                """
                UPDATE setting
                SET value = %s,
                    updated = now()
                WHERE key = %s
                  AND deleted IS NULL
                RETURNING id, key, value, created, updated
                """,
                (value, normalized_key),
            ).fetchone()
            connection.commit()
        if not row:
            raise LookupError(f"Hovering configuration {normalized_key} does not exist.")
        return dict(row)

    def resolve_stale_dates(self, *, business_day: date, record_ids: list[str] | None) -> int:
        clauses = [
            "status = 'PENDING'",
            "credit_account = %s",
            "type = %s",
            "installment_date::date < %s",
        ]
        params: list[Any] = [
            settings.NEXUS_HOVERING_CREDIT_ACCOUNT,
            settings.NEXUS_HOVERING_TYPE,
            business_day,
        ]
        if record_ids:
            clauses.append("id = ANY(%s)")
            params.append(record_ids)
        with self.connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"""
                    UPDATE hovering
                    SET installment_date = %s
                    WHERE {' AND '.join(clauses)}
                    """,
                    (business_day, *params),
                )
                updated = max(0, cursor.rowcount)
            connection.commit()
        return updated


class HoveringMonitorRepository:
    """SentinelOps-owned samples, policy, and immutable action history."""

    def __init__(self, dsn: str | None = None) -> None:
        self._dsn = dsn if dsn is not None else settings.nexus_database_dsn

    @contextmanager
    def _connection(self) -> Iterator[Any]:
        if not self._dsn:
            raise HoveringStorageError("Hovering monitor requires the shared SentinelOps DATABASE_URL.")
        try:
            with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
                yield connection
        except (psycopg.errors.UndefinedTable, psycopg.errors.UndefinedColumn) as exc:
            raise HoveringStorageError(
                "Hovering custody is not initialized. Apply the pending hovering migrations "
                f"through {HOVERING_FLOW_MIGRATION} and restart Nexus."
            ) from exc

    def get_policy(self) -> dict[str, Any]:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM nexus_hovering_policy WHERE policy_key = %s",
                (HOVERING_POLICY_KEY,),
            ).fetchone()
        if not row:
            raise HoveringStorageError(
                f"Hovering custody policy is missing. Apply {HOVERING_MIGRATION} and restart Nexus."
            )
        return dict(row)

    def set_policy(self, *, enabled: bool, changed_by: str, local_day: date) -> dict[str, Any]:
        with self._connection() as connection:
            with connection.cursor() as cursor:
                current = cursor.execute(
                    "SELECT enabled FROM nexus_hovering_policy WHERE policy_key = %s FOR UPDATE",
                    (HOVERING_POLICY_KEY,),
                ).fetchone()
                if not current:
                    raise HoveringStorageError(
                        f"Hovering custody policy is missing. Apply {HOVERING_MIGRATION} and restart Nexus."
                    )
                previous = bool(current["enabled"])
                cursor.execute(
                    """
                    UPDATE nexus_hovering_policy
                    SET enabled = %s,
                        updated_by = %s,
                        updated_at = now(),
                        last_run_day = CASE WHEN %s AND NOT enabled THEN %s ELSE last_run_day END
                    WHERE policy_key = %s
                    """,
                    (enabled, changed_by, enabled, local_day, HOVERING_POLICY_KEY),
                )
                if previous != enabled:
                    cursor.execute(
                        """
                        INSERT INTO nexus_hovering_policy_audit (
                            audit_id, policy_key, previous_enabled, enabled, changed_by
                        ) VALUES (%s, %s, %s, %s, %s)
                        """,
                        (f"hovering-policy-{uuid4()}", HOVERING_POLICY_KEY, previous, enabled, changed_by),
                    )
            connection.commit()
        return self.get_policy()

    def claim_rollover(self, local_day: date) -> bool:
        with self._connection() as connection:
            row = connection.execute(
                """
                UPDATE nexus_hovering_policy
                SET last_run_day = %s,
                    last_run_at = now(),
                    last_run_status = 'RUNNING',
                    last_error = NULL
                WHERE policy_key = %s
                  AND enabled = TRUE
                  AND last_run_day IS DISTINCT FROM %s
                RETURNING policy_key
                """,
                (local_day, HOVERING_POLICY_KEY, local_day),
            ).fetchone()
            connection.commit()
        return bool(row)

    def finish_rollover(self, *, updated_count: int, status: str, error: str | None = None) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                UPDATE nexus_hovering_policy
                SET last_updated_count = %s,
                    last_run_status = %s,
                    last_error = %s
                WHERE policy_key = %s
                """,
                (updated_count, status, error, HOVERING_POLICY_KEY),
            )
            connection.commit()

    def save_sample(self, *, observed_at: datetime, counts: dict[str, Any]) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO nexus_hovering_queue_sample (
                    observed_at, pending_count, overdue_count, due_today_count, future_count,
                    latest_queue_update, created_count
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    observed_at,
                    int(counts.get("pending_count") or 0),
                    int(counts.get("overdue_count") or 0),
                    int(counts.get("due_today_count") or 0),
                    int(counts.get("future_count") or 0),
                    counts.get("latest_queue_update"),
                    int(counts.get("created_count") or 0),
                ),
            )
            connection.execute(
                "DELETE FROM nexus_hovering_queue_sample WHERE observed_at < now() - interval '14 days'"
            )
            connection.commit()

    def recent_samples(self, *, since: datetime) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT observed_at, pending_count, overdue_count, due_today_count, future_count,
                       latest_queue_update, created_count
                FROM nexus_hovering_queue_sample
                WHERE observed_at >= %s
                ORDER BY observed_at
                """,
                (since,),
            ).fetchall()
        return [dict(row) for row in rows]

    def record_date_action(
        self,
        *,
        trigger: str,
        actor: str,
        requested_ids: list[str] | None,
        updated_count: int,
        status: str,
        error: str | None = None,
    ) -> dict[str, Any]:
        action_id = f"hovering-date-action-{uuid4()}"
        with self._connection() as connection:
            row = connection.execute(
                """
                INSERT INTO nexus_hovering_date_action (
                    action_id, trigger, actor, requested_ids, updated_count, status, error_message
                ) VALUES (%s, %s, %s, %s::jsonb, %s, %s, %s)
                RETURNING *
                """,
                (
                    action_id,
                    trigger,
                    actor,
                    psycopg.types.json.Jsonb(requested_ids or []),
                    updated_count,
                    status,
                    error,
                ),
            ).fetchone()
            connection.commit()
        return dict(row)

    def recent_actions(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM nexus_hovering_date_action
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (max(1, min(limit, 100)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def policy_audit(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM nexus_hovering_policy_audit
                ORDER BY changed_at DESC
                LIMIT %s
                """,
                (max(1, min(limit, 100)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def record_setting_action(
        self,
        *,
        setting_key: str,
        setting_kind: str,
        actor: str,
        status: str,
        error: str | None = None,
    ) -> dict[str, Any]:
        with self._connection() as connection:
            row = connection.execute(
                """
                INSERT INTO nexus_hovering_setting_action (
                    action_id, setting_key, setting_kind, actor, status, error_message
                ) VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING *
                """,
                (
                    f"hovering-setting-{uuid4()}",
                    setting_key,
                    setting_kind,
                    actor,
                    status,
                    error,
                ),
            ).fetchone()
            connection.commit()
        return dict(row)

    def recent_setting_actions(self, limit: int = 30) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM nexus_hovering_setting_action
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (max(1, min(limit, 100)),),
            ).fetchall()
        return [dict(row) for row in rows]


class HoveringMonitorService:
    def __init__(
        self,
        repository: HoveringMonitorRepository | None = None,
        gateway: HoveringQueueGateway | None = None,
        encryptor: RobotPasswordEncryptor | None = None,
    ) -> None:
        self.repository = repository or HoveringMonitorRepository()
        self.gateway = gateway or HoveringQueueGateway()
        self.encryptor = encryptor or RobotPasswordEncryptor()

    @property
    def zone(self) -> ZoneInfo:
        return ZoneInfo(settings.NEXUS_HOVERING_TIMEZONE)

    @property
    def window_start(self) -> time:
        return _parse_clock(settings.NEXUS_HOVERING_BOT_WINDOW_START, "NEXUS_HOVERING_BOT_WINDOW_START")

    @property
    def window_end(self) -> time:
        return _parse_clock(settings.NEXUS_HOVERING_BOT_WINDOW_END, "NEXUS_HOVERING_BOT_WINDOW_END")

    @property
    def weekend_window_end(self) -> time:
        return _parse_clock(
            settings.NEXUS_HOVERING_WEEKEND_WINDOW_END,
            "NEXUS_HOVERING_WEEKEND_WINDOW_END",
        )

    def window_end_for(self, day: date) -> time:
        return self.weekend_window_end if day.weekday() >= 5 else self.window_end

    def local_now(self) -> datetime:
        return datetime.now(timezone.utc).astimezone(self.zone)

    def _next_window_at(self, now: datetime) -> datetime:
        local = now.astimezone(self.zone)
        today_start = datetime.combine(local.date(), self.window_start, tzinfo=self.zone)
        if local < today_start:
            return today_start
        return today_start + timedelta(days=1)

    def overview(self) -> dict[str, Any]:
        now = self.local_now()
        policy = self.repository.get_policy()
        actions = self.repository.recent_actions()
        policy_audit = self.repository.policy_audit()
        current_window_end = self.window_end_for(now.date())
        window_mode = "WEEKEND" if now.weekday() >= 5 else "WEEKDAY"
        base: dict[str, Any] = {
            "configured": self.gateway.configured,
            "source_error": None,
            "refreshed_at": now,
            "timezone": settings.NEXUS_HOVERING_TIMEZONE,
            "credit_account": settings.NEXUS_HOVERING_CREDIT_ACCOUNT,
            "queue_type": settings.NEXUS_HOVERING_TYPE,
            "window": {
                "start": settings.NEXUS_HOVERING_BOT_WINDOW_START,
                "end": current_window_end.strftime("%H:%M"),
                "weekday_end": settings.NEXUS_HOVERING_BOT_WINDOW_END,
                "weekend_end": settings.NEXUS_HOVERING_WEEKEND_WINDOW_END,
                "mode": window_mode,
                "next_start_at": self._next_window_at(now),
            },
            "policy": policy,
            "date_actions": actions,
            "policy_audit": policy_audit,
            "counts": None,
            "movement": None,
        }
        if not self.gateway.configured:
            base["source_error"] = "Set TXN_BOT_DATABASE_URL to open the hovering queue."
            return base
        try:
            counts = self.gateway.counts(business_day=now.date())
            samples = self.repository.recent_samples(
                since=now - timedelta(minutes=max(15, settings.NEXUS_HOVERING_RATE_WINDOW_MINUTES))
            )
            movement = derive_movement(
                samples,
                pending_count=int(counts.get("pending_count") or 0),
                created_count=int(counts.get("created_count") or 0),
                now=now,
                zone=self.zone,
                window_start=self.window_start,
                window_end=self.window_end,
                weekend_window_end=self.weekend_window_end,
                stall_minutes=settings.NEXUS_HOVERING_STALL_MINUTES,
            )
            local_time = now.time().replace(tzinfo=None)
            window_seconds = (
                datetime.combine(now.date(), current_window_end)
                - datetime.combine(now.date(), self.window_start)
            ).total_seconds()
            elapsed = max(
                0.0,
                min(
                    window_seconds,
                    (
                        now.replace(tzinfo=None) - datetime.combine(now.date(), self.window_start)
                    ).total_seconds(),
                ),
            )
            base["counts"] = counts
            base["movement"] = {
                "posture": movement.posture,
                "rate_per_hour": movement.rate_per_hour,
                "arrival_rate_per_hour": movement.arrival_rate_per_hour,
                "net_rate_per_hour": movement.net_rate_per_hour,
                "processed_count": movement.processed_count,
                "arrived_count": movement.arrived_count,
                "net_change": movement.net_change,
                "last_movement_at": movement.last_movement_at,
                "observed_active_minutes": movement.observed_active_minutes,
                "window_open": self.window_start <= local_time < current_window_end,
                "window_progress": round(elapsed / window_seconds * 100, 1) if window_seconds else 0,
                "active_hours_to_clear": (
                    round(int(counts.get("pending_count") or 0) / movement.net_rate_per_hour, 1)
                    if movement.net_rate_per_hour > 0
                    else None
                ),
            }
        except Exception as exc:
            logger.exception("Hovering queue overview failed")
            base["source_error"] = str(exc)
        return base

    def records(self, **filters: Any) -> dict[str, Any]:
        return self.gateway.records(**filters)

    def settings_overview(self, *, include_configurations: bool) -> dict[str, Any]:
        source = self.gateway.settings()
        return {
            "configured": self.gateway.configured,
            "encryption_configured": self.encryptor.configured,
            "robots": source["robots"],
            "configurations": source["configurations"] if include_configurations else [],
            "configuration_access": include_configurations,
            "recent_actions": self.repository.recent_setting_actions(),
        }

    def _record_setting_action(
        self,
        *,
        setting_key: str,
        setting_kind: str,
        actor: str,
        status: str,
        error: str | None = None,
    ) -> bool:
        try:
            self.repository.record_setting_action(
                setting_key=setting_key,
                setting_kind=setting_kind,
                actor=actor,
                status=status,
                error=error,
            )
            return True
        except Exception:
            logger.exception("Unable to retain hovering setting custody for %s", setting_key)
            return False

    def rotate_robot_password(self, *, key: str, password: str, actor: str) -> dict[str, Any]:
        normalized_key = key.strip().upper()
        if not ROBOT_SETTING_PATTERN.fullmatch(normalized_key):
            raise ValueError("Only ROBHOV robot credentials can use the password rotation path.")
        self.repository.recent_setting_actions(limit=1)
        try:
            encrypted = self.encryptor.encrypt(password)
            updated = self.gateway.update_robot_credential(
                key=normalized_key,
                encrypted_value=encrypted,
            )
        except Exception as exc:
            self._record_setting_action(
                setting_key=normalized_key,
                setting_kind="ROBOT_PASSWORD",
                actor=actor,
                status="FAILED",
                error=str(exc),
            )
            audit_logger.log(
                event_type="nexus_hovering_robot_password",
                user=actor,
                details={"setting_key": normalized_key},
                success=False,
            )
            raise
        custody_recorded = self._record_setting_action(
            setting_key=normalized_key,
            setting_kind="ROBOT_PASSWORD",
            actor=actor,
            status="COMPLETED",
        )
        audit_logger.log(
            event_type="nexus_hovering_robot_password",
            user=actor,
            details={"setting_key": normalized_key, "custody_recorded": custody_recorded},
            success=True,
        )
        return {**updated, "custody_recorded": custody_recorded}

    def update_general_configuration(self, *, key: str, value: str, actor: str) -> dict[str, Any]:
        normalized_key = key.strip().upper()
        if ROBOT_SETTING_PATTERN.fullmatch(normalized_key):
            raise ValueError("Robot credentials must use the protected password rotation path.")
        self.repository.recent_setting_actions(limit=1)
        try:
            updated = self.gateway.update_configuration(key=normalized_key, value=value)
        except Exception as exc:
            self._record_setting_action(
                setting_key=normalized_key,
                setting_kind="GENERAL_CONFIGURATION",
                actor=actor,
                status="FAILED",
                error=str(exc),
            )
            audit_logger.log(
                event_type="nexus_hovering_configuration",
                user=actor,
                details={"setting_key": normalized_key},
                success=False,
            )
            raise
        custody_recorded = self._record_setting_action(
            setting_key=normalized_key,
            setting_kind="GENERAL_CONFIGURATION",
            actor=actor,
            status="COMPLETED",
        )
        audit_logger.log(
            event_type="nexus_hovering_configuration",
            user=actor,
            details={"setting_key": normalized_key, "custody_recorded": custody_recorded},
            success=True,
        )
        return {**updated, "custody_recorded": custody_recorded}

    def set_policy(self, *, enabled: bool, actor: str) -> dict[str, Any]:
        policy = self.repository.set_policy(enabled=enabled, changed_by=actor, local_day=self.local_now().date())
        audit_logger.log(
            event_type="nexus_hovering_policy",
            user=actor,
            details={"enabled": enabled, "policy_key": HOVERING_POLICY_KEY},
            success=True,
        )
        return policy

    def resolve_dates(
        self,
        *,
        actor: str,
        trigger: Literal["MANUAL", "SCHEDULED"],
        record_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        if record_ids and len(record_ids) > 500:
            raise ValueError("A manual date repair can contain at most 500 queue records.")
        try:
            updated = self.gateway.resolve_stale_dates(
                business_day=self.local_now().date(),
                record_ids=record_ids,
            )
            action = self.repository.record_date_action(
                trigger=trigger,
                actor=actor,
                requested_ids=record_ids,
                updated_count=updated,
                status="COMPLETED",
            )
            audit_logger.log(
                event_type="nexus_hovering_date_repair",
                user=actor,
                details={"trigger": trigger, "updated_count": updated, "record_ids": record_ids or []},
                success=True,
            )
            return action
        except Exception as exc:
            try:
                self.repository.record_date_action(
                    trigger=trigger,
                    actor=actor,
                    requested_ids=record_ids,
                    updated_count=0,
                    status="FAILED",
                    error=str(exc),
                )
            except Exception:
                logger.exception("Unable to retain failed hovering date action")
            audit_logger.log(
                event_type="nexus_hovering_date_repair",
                user=actor,
                details={"trigger": trigger, "error": str(exc)},
                success=False,
            )
            raise

    def tick(self) -> None:
        now = self.local_now()
        if self.gateway.configured:
            counts = self.gateway.counts(business_day=now.date())
            self.repository.save_sample(observed_at=now, counts=counts)
        if not self.gateway.configured or not self.repository.claim_rollover(now.date()):
            return
        try:
            action = self.resolve_dates(actor="hovering-scheduler", trigger="SCHEDULED")
            self.repository.finish_rollover(
                updated_count=int(action.get("updated_count") or 0),
                status="COMPLETED",
            )
        except Exception as exc:
            self.repository.finish_rollover(updated_count=0, status="FAILED", error=str(exc))
            logger.exception("Automatic hovering installment-date rollover failed")


class HoveringMonitorScheduler:
    def __init__(self, service: HoveringMonitorService) -> None:
        self.service = service
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        await asyncio.to_thread(self.service.repository.get_policy)
        self._stop.clear()
        self._task = asyncio.create_task(self._run(), name="sentinelops-hovering-monitor")

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            await self._task
            self._task = None

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.to_thread(self.service.tick)
            except Exception:
                logger.exception("Hovering monitor tick failed")
            try:
                await asyncio.wait_for(
                    self._stop.wait(),
                    timeout=max(15, settings.NEXUS_HOVERING_SAMPLE_INTERVAL_SECONDS),
                )
            except asyncio.TimeoutError:
                continue
