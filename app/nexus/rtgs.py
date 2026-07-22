"""Guarded RTGS in-transit assessment and regeneration orchestration.

Assessment is deliberately read-only. Mutation is limited to the allowlisted
Oracle regeneration package and always revalidates the current database row
immediately before it runs.
"""

from __future__ import annotations

import asyncio
import json
import re
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4
from zoneinfo import ZoneInfo

import psycopg
from psycopg.rows import dict_row

from app.config.settings import settings
from app.nexus.models import (
    RTGSActionRequest,
    RTGSActionResult,
    RTGSAssessment,
    RTGSAutoRegenerationAuditEntry,
    RTGSAutoRegenerationPolicy,
    RTGSSchedule,
    RTGSScheduleRequest,
    RTGSRegenerationHistoryEntry,
    RTGSTransactionCase,
)
from app.utils.audit import audit_logger
from app.utils.logging import get_logger


logger = get_logger(__name__)
TRANSACTION_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9_-]{5,63}$")
REGENERATION_PACKAGE_RE = re.compile(r"^PKG_EFTORCLADVQ\.WRITE_TO_FINOUTQPE$", re.IGNORECASE)
AUTO_POLICY_MIGRATION = "2026_07_add_nexus_rtgs_auto_regeneration.sql"


@contextmanager
def _translate_auto_policy_storage_error():
    try:
        yield
    except psycopg.errors.UndefinedTable as exc:
        raise RuntimeError(
            "RTGS automatic regeneration storage is not initialized. "
            f"Apply {AUTO_POLICY_MIGRATION} and restart Nexus."
        ) from exc


def _rtgs_zone() -> ZoneInfo:
    try:
        return ZoneInfo(settings.RTGS_TIMEZONE)
    except Exception:
        return ZoneInfo("UTC")


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=_rtgs_zone())
    return value


def age_lane_for(age_hours: float) -> str:
    if age_hours < 24:
        return "0_24H"
    if age_hours < 48:
        return "24_48H"
    if age_hours < 72:
        return "48_72H"
    if age_hours < 96:
        return "72_96H"
    return "OVER_96H"


def make_case(row: dict[str, Any], assessed_at: datetime) -> RTGSTransactionCase:
    entry_date = _aware(row["entry_date"])
    now = _aware(assessed_at)
    age_hours = max(0.0, (now - entry_date).total_seconds() / 3600)
    lane = age_lane_for(age_hours)
    queue_instance_ids = [str(value) for value in row.get("queue_instance_ids", []) if value not in (None, "")]
    warnings: list[str] = []
    if lane == "OVER_96H":
        warnings.append("Older than 96 hours; confirm treasury or reconciliation ownership before any recovery action.")
    if not queue_instance_ids:
        warnings.append("No outbound queue instance is linked to this transaction; regeneration is not available.")
    return RTGSTransactionCase(
        transaction_id=str(row["transaction_id"]),
        status=str(row.get("transaction_status") or "IN_TRANSIT"),
        entry_date=entry_date,
        age_hours=round(age_hours, 2),
        age_lane=lane,
        branch_code=str(row.get("branch_code") or "") or None,
        entry_sequence=str(row.get("entry_sequence") or "") or None,
        message_type=str(row.get("message_type") or settings.RTGS_MESSAGE_TYPE),
        queue_instance_ids=queue_instance_ids,
        regeneration_ready=bool(queue_instance_ids),
        recommendation="REGENERATE" if queue_instance_ids else "QUEUE_CONTEXT_MISSING",
        warnings=warnings,
        assessed_at=assessed_at,
    )


def _normalize_stored_assessment(payload: dict[str, Any]) -> dict[str, Any]:
    """Read pre-database-only assessments without reviving their old contract."""
    normalized = dict(payload)
    raw_cases = normalized.get("cases") or []
    cases: list[dict[str, Any]] = []
    for raw_case in raw_cases:
        case = dict(raw_case or {})
        queue_instance_ids = [
            str(value)
            for value in (case.get("queue_instance_ids") or [])
            if value not in (None, "")
        ]
        regeneration_ready = bool(case.get("regeneration_ready", bool(queue_instance_ids)))
        case["queue_instance_ids"] = queue_instance_ids
        case["regeneration_ready"] = regeneration_ready
        case["recommendation"] = "REGENERATE" if regeneration_ready else "QUEUE_CONTEXT_MISSING"
        case["status"] = str(case.get("status") or "IN_TRANSIT")
        case["settlement_note"] = str(
            case.get("settlement_note")
            or "Transaction remains IN_TRANSIT; settlement has not cleared the case."
        )
        if not isinstance(case.get("warnings"), list):
            case["warnings"] = []
        case.pop("file_state", None)
        case.pop("files", None)
        cases.append(case)

    normalized["cases"] = cases
    normalized["transaction_count"] = len(cases)
    normalized["trigger"] = "manual" if normalized.get("trigger") == "manual" else "scheduled"
    normalized["status"] = normalized.get("status") if normalized.get("status") in {"COMPLETED", "PARTIAL", "FAILED"} else "COMPLETED"
    normalized["interpretation"] = (
        f"Stored Oracle assessment read {len(cases)} transaction(s). "
        "Run a fresh assessment before requesting regeneration."
    )
    normalized["message"] = (
        f"Stored database assessment contains {len(cases)} transaction(s); "
        "a fresh read is required before action."
    )
    return normalized


class RTGSOracleGateway:
    """Read current RTGS state and invoke only the approved regeneration package."""

    LIST_SQL = """
        SELECT DISTINCT
            y.efti_txnid AS transaction_id,
            y.efti_status AS transaction_status,
            ee.eftcp_brn_code AS branch_code,
            ee.eftcp_entry_date AS entry_date,
            ee.eftcp_entry_sl AS entry_sequence,
            ee.eftcp_msgtype AS message_type,
            e.eftfqpe_instance_id AS queue_instance_id
        FROM eftcpymtk2 ee
        JOIN eftcmninqk2 y
          ON ee.eftcp_brn_code = y.efti_brn
         AND ee.eftcp_entry_date = y.efti_entry_rcpt_date
         AND ee.eftcp_entry_sl = y.efti_msgsl
         AND ee.eftcp_msgtype = y.efti_msgtype
        LEFT JOIN eftfinoutqpe e
          ON e.eftfqpe_src_brn = ee.eftcp_brn_code
         AND e.eftfqpe_src_date = ee.eftcp_entry_date
         AND e.eftfqpe_src_primary_sl = ee.eftcp_entry_sl
        WHERE ee.eftcp_entity_num = :entity_num
          AND ee.eftcp_msgtype = :message_type
          AND y.efti_status = 'IN_TRANSIT'
        ORDER BY ee.eftcp_entry_date DESC, y.efti_txnid
    """

    def list_current_transactions(self) -> list[dict[str, Any]]:
        return self._query(self.LIST_SQL)

    def get_current_transaction(self, transaction_id: str) -> dict[str, Any] | None:
        self._validate_transaction_id(transaction_id)
        rows = self._query(self.LIST_SQL + "", extra_bind={"transaction_id": transaction_id}, add_filter=True)
        return rows[0] if rows else None

    def regenerate(self, row: dict[str, Any]) -> str:
        if not settings.RTGS_REGENERATION_ENABLED:
            raise RuntimeError("RTGS regeneration is disabled until the approved production package is explicitly enabled.")
        if not REGENERATION_PACKAGE_RE.fullmatch(settings.RTGS_REGENERATION_PACKAGE.strip()):
            raise RuntimeError("Configured regeneration callable is not on the Nexus allowlist.")
        instance_id = row.get("queue_instance_ids", [None])[0]
        if instance_id in (None, ""):
            raise RuntimeError("No outbound queue instance is available for this transaction.")

        connection = self._connect(read_only=False)
        try:
            cursor = connection.cursor()
            try:
                error_var = cursor.var(str, arraysize=1)
                cursor.callproc(
                    settings.RTGS_REGENERATION_PACKAGE,
                    [settings.RTGS_ENTITY_NUMBER, instance_id, error_var],
                )
                error_text = str(error_var.getvalue() or "").strip()
                if error_text:
                    connection.rollback()
                    raise RuntimeError(f"Approved RTGS regeneration returned an error: {error_text}")
                connection.commit()
                return "Approved regeneration package completed without an Oracle error response."
            finally:
                cursor.close()
        except Exception:
            try:
                connection.rollback()
            except Exception:
                pass
            raise
        finally:
            connection.close()

    def _query(
        self,
        sql: str,
        *,
        extra_bind: dict[str, Any] | None = None,
        add_filter: bool = False,
    ) -> list[dict[str, Any]]:
        if not settings.rtgs_oracle_enabled:
            raise RuntimeError("RTGS Oracle assessment is disabled until its read-only connection is configured.")
        query = sql
        if add_filter:
            query = query.replace(
                "ORDER BY ee.eftcp_entry_date DESC, y.efti_txnid",
                "AND y.efti_txnid = :transaction_id ORDER BY ee.eftcp_entry_date DESC, y.efti_txnid",
            )
        connection = self._connect(read_only=True)
        try:
            cursor = connection.cursor()
            try:
                binds = {"entity_num": settings.RTGS_ENTITY_NUMBER, "message_type": settings.RTGS_MESSAGE_TYPE}
                binds.update(extra_bind or {})
                cursor.execute(query, binds)
                columns = [str(item[0]).lower() for item in cursor.description]
                grouped: dict[str, dict[str, Any]] = {}
                for raw_row in cursor.fetchall():
                    row = dict(zip(columns, raw_row))
                    txid = str(row["transaction_id"])
                    existing = grouped.setdefault(
                        txid,
                        {
                            "transaction_id": txid,
                            "transaction_status": row.get("transaction_status") or "IN_TRANSIT",
                            "entry_date": row["entry_date"],
                            "branch_code": row.get("branch_code"),
                            "entry_sequence": row.get("entry_sequence"),
                            "message_type": row.get("message_type"),
                            "queue_instance_ids": [],
                        },
                    )
                    if row.get("queue_instance_id") not in (None, ""):
                        existing["queue_instance_ids"].append(row["queue_instance_id"])
                return list(grouped.values())
            finally:
                cursor.close()
        finally:
            connection.close()

    def _connect(self, *, read_only: bool):
        try:
            import oracledb
        except ImportError as exc:
            raise RuntimeError("The optional 'oracledb' package is required for RTGS assessment.") from exc
        username = settings.RTGS_ORACLE_USERNAME or settings.ORACLE_USER
        password = settings.RTGS_ORACLE_PASSWORD or settings.ORACLE_PASSWORD
        dsn = settings.RTGS_ORACLE_DSN or settings.ORACLE_DSN
        if not dsn and settings.IDC_ORACLE_HOST and (settings.ORACLE_SID or settings.ORACLE_SERVICE or settings.ORACLE_SERVICE_NAME):
            try:
                port = int(settings.ORACLE_PORT or "1521")
            except ValueError as exc:
                raise RuntimeError("ORACLE_PORT must be a valid number.") from exc
            service_name = settings.ORACLE_SERVICE_NAME or settings.ORACLE_SERVICE
            if settings.ORACLE_SID:
                dsn = oracledb.makedsn(settings.IDC_ORACLE_HOST, port, sid=settings.ORACLE_SID)
            else:
                dsn = oracledb.makedsn(settings.IDC_ORACLE_HOST, port, service_name=service_name)
        if not dsn or not username or not password:
            raise RuntimeError(
                "RTGS Oracle connection is incomplete. Configure ORACLE_USER, ORACLE_PASSWORD, "
                "IDC_ORACLE_HOST, ORACLE_PORT, and ORACLE_SID (or RTGS_* overrides)."
            )
        connection = oracledb.connect(
            user=username,
            password=password.get_secret_value(),
            dsn=dsn,
            config_dir=settings.RTGS_ORACLE_CONFIG_DIR or None,
            tcp_connect_timeout=settings.ORACLE_CONNECT_TIMEOUT_SECONDS,
        )
        if read_only:
            cursor = connection.cursor()
            try:
                cursor.execute("SET TRANSACTION READ ONLY")
            finally:
                cursor.close()
        return connection

    @staticmethod
    def _validate_transaction_id(transaction_id: str) -> None:
        if not TRANSACTION_ID_RE.fullmatch(transaction_id.strip()):
            raise ValueError("Invalid RTGS transaction identifier.")


class RTGSRepository:
    """Small append-only ledger for RTGS assessment and action evidence."""

    def __init__(self) -> None:
        self._dsn = settings.nexus_database_dsn
        self._local_path = settings.DATA_DIR / "rtgs_state.json"
        self._local_schedule_marks: dict[str, datetime] = {}
        self._local_action_locks: dict[str, threading.Lock] = {}
        self._local_auto_policy = RTGSAutoRegenerationPolicy()
        self._local_auto_audit: list[RTGSAutoRegenerationAuditEntry] = []

    def save_assessment(self, assessment: RTGSAssessment) -> None:
        if not self._dsn:
            self._save_local(assessment)
            return
        payload = assessment.model_dump(mode="json")
        with psycopg.connect(self._dsn, row_factory=dict_row) as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO nexus_rtgs_assessment (assessment_id, trigger, assessed_at, transaction_count, status, payload)
                       VALUES (%s, %s, %s, %s, %s, %s::jsonb)""",
                    (assessment.assessment_id, assessment.trigger, assessment.assessed_at, assessment.transaction_count, assessment.status, json.dumps(payload)),
                )
                for case in assessment.cases:
                    case_payload = case.model_dump(mode="json")
                    cursor.execute(
                        """INSERT INTO nexus_rtgs_case (assessment_id, transaction_id, assessed_at, entry_date, age_lane, recommendation, payload)
                           VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)""",
                        (assessment.assessment_id, case.transaction_id, case.assessed_at, case.entry_date, case.age_lane, case.recommendation, json.dumps(case_payload)),
                    )
            conn.commit()

    def latest_assessment(self) -> RTGSAssessment | None:
        if not self._dsn:
            return self._load_local()
        with psycopg.connect(self._dsn, row_factory=dict_row) as conn:
            with conn.cursor() as cursor:
                row = cursor.execute("SELECT payload FROM nexus_rtgs_assessment ORDER BY assessed_at DESC LIMIT 1").fetchone()
        return RTGSAssessment.model_validate(_normalize_stored_assessment(row["payload"])) if row else None

    def get_action(self, idempotency_key: str) -> RTGSActionResult | None:
        if not self._dsn:
            return None
        with psycopg.connect(self._dsn, row_factory=dict_row) as conn:
            with conn.cursor() as cursor:
                row = cursor.execute("SELECT payload FROM nexus_rtgs_action WHERE idempotency_key = %s", (idempotency_key,)).fetchone()
        if not row:
            return None
        try:
            return RTGSActionResult.model_validate(row["payload"])
        except Exception:
            logger.warning("Ignoring an action ledger row from the retired RTGS action contract: %s", idempotency_key)
            return None

    def save_action(self, result: RTGSActionResult, idempotency_key: str | None, reason: str) -> None:
        if not self._dsn:
            return
        with psycopg.connect(self._dsn, row_factory=dict_row) as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO nexus_rtgs_action (action_id, idempotency_key, transaction_id, action, status, requested_by, reason, created_at, payload)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)""",
                    (result.action_id, idempotency_key, result.transaction_id, result.action, result.status, result.requested_by, reason, result.created_at, json.dumps(result.model_dump(mode="json"))),
                )
            conn.commit()

    def list_actions(self, limit: int = 100) -> list[RTGSRegenerationHistoryEntry]:
        if not self._dsn:
            return []
        with psycopg.connect(self._dsn, row_factory=dict_row) as conn:
            with conn.cursor() as cursor:
                rows = cursor.execute(
                    """SELECT action_id, transaction_id, status, requested_by, reason, created_at, payload
                       FROM nexus_rtgs_action
                       WHERE action = 'regenerate'
                       ORDER BY created_at DESC
                       LIMIT %s""",
                    (max(1, min(limit, 500)),),
                ).fetchall()
        history: list[RTGSRegenerationHistoryEntry] = []
        for row in rows:
            payload = dict(row.get("payload") or {})
            verification = dict(payload.get("verification") or {})
            mode = "automatic" if verification.get("execution_mode") == "automatic" else "manual"
            history.append(
                RTGSRegenerationHistoryEntry(
                    action_id=row["action_id"],
                    transaction_id=row["transaction_id"],
                    status=row["status"],
                    requested_by=row["requested_by"],
                    reason=row["reason"],
                    mode=mode,
                    message=str(payload.get("message") or "Regeneration action recorded."),
                    verification=verification,
                    created_at=row["created_at"],
                )
            )
        return history

    def completed_automatic_transaction_ids(self, transaction_ids: list[str]) -> set[str]:
        if not self._dsn or not transaction_ids:
            return set()
        with psycopg.connect(self._dsn, row_factory=dict_row) as conn:
            with conn.cursor() as cursor:
                rows = cursor.execute(
                    """SELECT DISTINCT transaction_id
                       FROM nexus_rtgs_action
                       WHERE transaction_id = ANY(%s)
                         AND action = 'regenerate'
                         AND status = 'COMPLETED'
                         AND payload->'verification'->>'execution_mode' = 'automatic'""",
                    (transaction_ids,),
                ).fetchall()
        return {str(row["transaction_id"]) for row in rows}

    def get_auto_policy(self) -> RTGSAutoRegenerationPolicy:
        if not self._dsn:
            return self._local_auto_policy
        with _translate_auto_policy_storage_error():
            with psycopg.connect(self._dsn, row_factory=dict_row) as conn:
                with conn.cursor() as cursor:
                    row = cursor.execute(
                        """SELECT policy_key, enabled, window_days, updated_by, updated_at,
                                  last_run_at, last_attempted_count, last_completed_count, last_run_status
                           FROM nexus_rtgs_auto_policy
                           WHERE policy_key = 'latest-five-day-window'"""
                    ).fetchone()
        return RTGSAutoRegenerationPolicy.model_validate(row) if row else RTGSAutoRegenerationPolicy()

    def set_auto_policy(self, *, enabled: bool, changed_by: str) -> RTGSAutoRegenerationPolicy:
        now = datetime.now(timezone.utc)
        if not self._dsn:
            previous_enabled = self._local_auto_policy.enabled
            self._local_auto_policy = self._local_auto_policy.model_copy(
                update={"enabled": enabled, "updated_by": changed_by, "updated_at": now}
            )
            if previous_enabled != enabled:
                self._local_auto_audit.insert(
                    0,
                    RTGSAutoRegenerationAuditEntry(
                        audit_id=f"rtgs-auto-audit-{uuid4()}",
                        previous_enabled=previous_enabled,
                        enabled=enabled,
                        changed_by=changed_by,
                        changed_at=now,
                    ),
                )
            return self._local_auto_policy

        with _translate_auto_policy_storage_error():
            with psycopg.connect(self._dsn, row_factory=dict_row) as conn:
                with conn.cursor() as cursor:
                    current = cursor.execute(
                        """SELECT enabled FROM nexus_rtgs_auto_policy
                           WHERE policy_key = 'latest-five-day-window'
                           FOR UPDATE"""
                    ).fetchone()
                    previous_enabled = bool(current["enabled"]) if current else False
                    cursor.execute(
                        """INSERT INTO nexus_rtgs_auto_policy
                               (policy_key, enabled, window_days, updated_by, updated_at)
                           VALUES ('latest-five-day-window', %s, 5, %s, %s)
                           ON CONFLICT (policy_key) DO UPDATE SET
                               enabled = EXCLUDED.enabled,
                               updated_by = EXCLUDED.updated_by,
                               updated_at = EXCLUDED.updated_at""",
                        (enabled, changed_by, now),
                    )
                    if previous_enabled != enabled:
                        cursor.execute(
                            """INSERT INTO nexus_rtgs_auto_policy_audit
                                   (audit_id, previous_enabled, enabled, changed_by, changed_at, window_days)
                               VALUES (%s, %s, %s, %s, %s, 5)""",
                            (f"rtgs-auto-audit-{uuid4()}", previous_enabled, enabled, changed_by, now),
                        )
                conn.commit()
        return self.get_auto_policy()

    def record_auto_run(self, *, attempted: int, completed: int, status: str) -> RTGSAutoRegenerationPolicy:
        now = datetime.now(timezone.utc)
        if not self._dsn:
            self._local_auto_policy = self._local_auto_policy.model_copy(
                update={
                    "last_run_at": now,
                    "last_attempted_count": attempted,
                    "last_completed_count": completed,
                    "last_run_status": status,
                }
            )
            return self._local_auto_policy
        with _translate_auto_policy_storage_error():
            with psycopg.connect(self._dsn, row_factory=dict_row) as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """UPDATE nexus_rtgs_auto_policy
                           SET last_run_at = %s,
                               last_attempted_count = %s,
                               last_completed_count = %s,
                               last_run_status = %s
                           WHERE policy_key = 'latest-five-day-window'""",
                        (now, attempted, completed, status),
                    )
                conn.commit()
        return self.get_auto_policy()

    def list_auto_policy_audit(self, limit: int = 100) -> list[RTGSAutoRegenerationAuditEntry]:
        if not self._dsn:
            return self._local_auto_audit[:limit]
        with _translate_auto_policy_storage_error():
            with psycopg.connect(self._dsn, row_factory=dict_row) as conn:
                with conn.cursor() as cursor:
                    rows = cursor.execute(
                        """SELECT audit_id, previous_enabled, enabled, changed_by, changed_at, window_days
                           FROM nexus_rtgs_auto_policy_audit
                           ORDER BY changed_at DESC
                           LIMIT %s""",
                        (max(1, min(limit, 500)),),
                    ).fetchall()
        return [RTGSAutoRegenerationAuditEntry.model_validate(row) for row in rows]

    def list_schedules(self) -> list[RTGSSchedule]:
        if not self._dsn:
            return []
        with psycopg.connect(self._dsn, row_factory=dict_row) as conn:
            with conn.cursor() as cursor:
                rows = cursor.execute("SELECT schedule_id, label, interval_minutes, local_time, timezone, enabled, last_triggered_at, created_by FROM nexus_rtgs_schedule ORDER BY updated_at DESC, label").fetchall()
        return [RTGSSchedule.model_validate(row) for row in rows]

    def save_schedule(self, schedule: RTGSSchedule) -> RTGSSchedule:
        if not self._dsn:
            return schedule
        with psycopg.connect(self._dsn, row_factory=dict_row) as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO nexus_rtgs_schedule (schedule_id, label, interval_minutes, local_time, timezone, enabled, created_by, updated_at)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, now())
                       ON CONFLICT (schedule_id) DO UPDATE SET label = EXCLUDED.label, interval_minutes = EXCLUDED.interval_minutes,
                         local_time = EXCLUDED.local_time, timezone = EXCLUDED.timezone, enabled = EXCLUDED.enabled, updated_at = now()""",
                    (schedule.schedule_id, schedule.label, schedule.interval_minutes, schedule.local_time, schedule.timezone, schedule.enabled, schedule.created_by),
                )
            conn.commit()
        return schedule

    def delete_schedule(self, schedule_id: str) -> None:
        if not self._dsn:
            return
        with psycopg.connect(self._dsn, row_factory=dict_row) as conn:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM nexus_rtgs_schedule WHERE schedule_id = %s", (schedule_id,))
            conn.commit()

    def claim_interval(self, schedule_id: str, interval_minutes: int, now: datetime) -> bool:
        """Claim one periodic interval, with a PostgreSQL advisory lock across workers."""
        if not self._dsn:
            previous = self._local_schedule_marks.get(schedule_id)
            if previous and (now - previous).total_seconds() < interval_minutes * 60:
                return False
            self._local_schedule_marks[schedule_id] = now
            return True
        with psycopg.connect(self._dsn, row_factory=dict_row) as conn:
            with conn.cursor() as cursor:
                locked = cursor.execute("SELECT pg_try_advisory_xact_lock(hashtext(%s)) AS locked", (schedule_id,)).fetchone()
                if not locked or not locked["locked"]:
                    return False
                row = cursor.execute("SELECT last_triggered_at FROM nexus_rtgs_schedule WHERE schedule_id = %s FOR UPDATE", (schedule_id,)).fetchone()
                if row and row["last_triggered_at"]:
                    previous = _aware(row["last_triggered_at"])
                    if (now - previous).total_seconds() < interval_minutes * 60:
                        return False
                cursor.execute("UPDATE nexus_rtgs_schedule SET last_triggered_at = %s, updated_at = now() WHERE schedule_id = %s", (now, schedule_id))
            conn.commit()
        return True

    @contextmanager
    def action_lock(self, key: str):
        """Hold a cross-worker lock for the full revalidation/mutation window."""
        if not self._dsn:
            lock = self._local_action_locks.setdefault(key, threading.Lock())
            if not lock.acquire(blocking=False):
                raise RuntimeError("An RTGS action for this transaction is already in progress.")
            try:
                yield
            finally:
                lock.release()
            return
        connection = psycopg.connect(self._dsn, row_factory=dict_row)
        try:
            with connection.cursor() as cursor:
                locked = cursor.execute("SELECT pg_try_advisory_lock(hashtext(%s)) AS locked", (key,)).fetchone()
                if not locked or not locked["locked"]:
                    raise RuntimeError("An RTGS action for this transaction is already in progress.")
            yield
        finally:
            connection.close()

    def _save_local(self, assessment: RTGSAssessment) -> None:
        if not settings.NEXUS_ALLOW_LOCAL_STATE:
            raise RuntimeError("RTGS persistence requires the shared SentinelOps database.")
        self._local_path.write_text(json.dumps(assessment.model_dump(mode="json"), indent=2), encoding="utf-8")

    def _load_local(self) -> RTGSAssessment | None:
        if not settings.NEXUS_ALLOW_LOCAL_STATE or not self._local_path.exists():
            return None
        payload = json.loads(self._local_path.read_text(encoding="utf-8"))
        return RTGSAssessment.model_validate(_normalize_stored_assessment(payload))


class RTGSAssessmentScheduler:
    """Periodic assessment loop with optional policy-gated regeneration."""

    def __init__(self, service: RTGSRecoveryService) -> None:
        self.service = service
        self._task: asyncio.Task[None] | None = None
        self._stopping = False

    async def start(self) -> None:
        if self._task is None:
            self._stopping = False
            self._task = asyncio.create_task(self._run(), name="sentinelops-rtgs-assessment-scheduler")

    async def stop(self) -> None:
        self._stopping = True
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _run(self) -> None:
        while not self._stopping:
            try:
                now = datetime.now(timezone.utc)
                for schedule in self.service.schedules():
                    if not schedule.enabled:
                        continue
                    if not self.service.repository.claim_interval(schedule.schedule_id, schedule.interval_minutes, now):
                        continue
                    try:
                        assessment = await asyncio.to_thread(self.service.assess, trigger="scheduled", requested_by=None)
                        await asyncio.to_thread(self.service.run_auto_regeneration, assessment)
                    except Exception:
                        logger.exception("Scheduled RTGS assessment failed for %s", schedule.schedule_id)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("RTGS assessment scheduler tick failed")
            await asyncio.sleep(30)


class RTGSRecoveryService:
    def __init__(self, repository: RTGSRepository | None = None, oracle: RTGSOracleGateway | None = None) -> None:
        self.repository = repository or RTGSRepository()
        self.oracle = oracle or RTGSOracleGateway()

    def assess(self, *, trigger: str, requested_by: str | None) -> RTGSAssessment:
        assessed_at = datetime.now(timezone.utc)
        rows = self.oracle.list_current_transactions()
        cases: list[RTGSTransactionCase] = []
        for row in rows:
            cases.append(make_case(row, assessed_at))
        missing_queue_context = sum(1 for case in cases if not case.regeneration_ready)
        interpretation = (
            f"Oracle read complete. {len(cases)} transaction(s) remain IN_TRANSIT. "
            f"{missing_queue_context} require queue-context review before regeneration."
        )
        assessment = RTGSAssessment(
            assessment_id=f"rtgs-assess-{uuid4()}",
            trigger="manual" if trigger == "manual" else "scheduled",
            assessed_at=assessed_at,
            transaction_count=len(cases),
            cases=cases,
            status="COMPLETED",
            interpretation=interpretation,
            message=f"Read-only database assessment found {len(cases)} current IN_TRANSIT transaction(s).",
        )
        self.repository.save_assessment(assessment)
        audit_logger.log(event_type="nexus_rtgs_assessment", user=requested_by or "rtgs-scheduler", details={"assessment_id": assessment.assessment_id, "count": len(cases), "trigger": trigger})
        return assessment

    def latest(self) -> RTGSAssessment | None:
        return self.repository.latest_assessment()

    def action_history(self, limit: int = 100) -> list[RTGSRegenerationHistoryEntry]:
        return self.repository.list_actions(limit)

    def auto_policy(self) -> RTGSAutoRegenerationPolicy:
        return self.repository.get_auto_policy()

    def set_auto_policy(self, *, enabled: bool, changed_by: str) -> RTGSAutoRegenerationPolicy:
        previous = self.repository.get_auto_policy()
        policy = self.repository.set_auto_policy(enabled=enabled, changed_by=changed_by)
        if previous.enabled != policy.enabled:
            audit_logger.log(
                event_type="nexus_rtgs_auto_regeneration_toggle",
                user=changed_by,
                details={
                    "previous_enabled": previous.enabled,
                    "enabled": policy.enabled,
                    "window_days": policy.window_days,
                },
            )
        return policy

    def auto_policy_audit(self, limit: int = 100) -> list[RTGSAutoRegenerationAuditEntry]:
        return self.repository.list_auto_policy_audit(limit)

    def run_auto_regeneration(self, assessment: RTGSAssessment) -> list[RTGSActionResult]:
        policy = self.repository.get_auto_policy()
        if not policy.enabled:
            return []

        cutoff = _aware(assessment.assessed_at) - timedelta(days=policy.window_days)
        in_window = [case for case in assessment.cases if _aware(case.entry_date) >= cutoff]
        candidates = [case for case in in_window if case.regeneration_ready]
        already_completed = self.repository.completed_automatic_transaction_ids(
            [case.transaction_id for case in candidates]
        )
        results: list[RTGSActionResult] = []
        for case in candidates:
            if case.transaction_id in already_completed:
                continue
            request = RTGSActionRequest(
                transaction_ids=[case.transaction_id],
                reason=f"Automatic RTGS regeneration policy: latest {policy.window_days}-day IN_TRANSIT window.",
                idempotency_key=f"rtgs-auto-{assessment.assessment_id}",
                confirm_over_96h=True,
            )
            results.append(
                self._execute_one(
                    request,
                    transaction_id=case.transaction_id,
                    requested_by="nexus-auto-regeneration",
                    execution_mode="automatic",
                    policy_updated_by=policy.updated_by,
                )
            )

        completed = sum(1 for result in results if result.status == "COMPLETED")
        blocked_context = any(not case.regeneration_ready for case in in_window)
        if not results:
            run_status = "PARTIAL" if blocked_context else "COMPLETED"
        elif completed == len(results) and not blocked_context:
            run_status = "COMPLETED"
        elif completed:
            run_status = "PARTIAL"
        else:
            run_status = "FAILED"
        self.repository.record_auto_run(attempted=len(results), completed=completed, status=run_status)
        audit_logger.log(
            event_type="nexus_rtgs_auto_regeneration_run",
            user="nexus-auto-regeneration",
            details={
                "assessment_id": assessment.assessment_id,
                "window_days": policy.window_days,
                "eligible": len(candidates),
                "attempted": len(results),
                "completed": completed,
                "status": run_status,
                "policy_updated_by": policy.updated_by,
            },
        )
        return results

    def schedules(self) -> list[RTGSSchedule]:
        schedules = self.repository.list_schedules()
        if schedules:
            # The product has one operator-selected cadence. Keep legacy rows from
            # creating duplicate assessments until the old checkpoint records are retired.
            return schedules[:1]
        item = settings.RTGS_DEFAULT_SCHEDULES[0] if settings.RTGS_DEFAULT_SCHEDULES else {}
        schedule = RTGSSchedule(
            schedule_id="rtgs-default-1",
            label=str(item.get("label") or "RTGS periodic assessment"),
            interval_minutes=30 if int(item.get("interval_minutes") or 30) == 30 else 60,
            local_time=str(item.get("local_time") or "00:00"),
            timezone=str(item.get("timezone") or settings.RTGS_TIMEZONE),
            created_by="system",
        )
        if self.repository._dsn:
            self.repository.save_schedule(schedule)
        return [schedule]

    def create_schedule(self, request: RTGSScheduleRequest, created_by: str) -> RTGSSchedule:
        try:
            ZoneInfo(request.timezone)
        except Exception as exc:
            raise ValueError("Unknown schedule timezone.") from exc
        schedule = RTGSSchedule(schedule_id=f"rtgs-schedule-{uuid4()}", label=request.label.strip(), interval_minutes=request.interval_minutes, local_time=request.local_time, timezone=request.timezone, enabled=request.enabled, created_by=created_by)
        return self.repository.save_schedule(schedule)

    def update_schedule(self, schedule_id: str, request: RTGSScheduleRequest, updated_by: str) -> RTGSSchedule:
        try:
            ZoneInfo(request.timezone)
        except Exception as exc:
            raise ValueError("Unknown schedule timezone.") from exc
        existing = next((item for item in self.schedules() if item.schedule_id == schedule_id), None)
        if existing is None:
            raise KeyError(f"Unknown RTGS schedule '{schedule_id}'.")
        updated = existing.model_copy(update={"label": request.label.strip(), "interval_minutes": request.interval_minutes, "local_time": request.local_time, "timezone": request.timezone, "enabled": request.enabled, "created_by": updated_by})
        return self.repository.save_schedule(updated)

    def delete_schedule(self, schedule_id: str) -> None:
        if not any(item.schedule_id == schedule_id for item in self.schedules()):
            raise KeyError(f"Unknown RTGS schedule '{schedule_id}'.")
        self.repository.delete_schedule(schedule_id)

    def execute(self, request: RTGSActionRequest, *, requested_by: str) -> list[RTGSActionResult]:
        assessment = self.latest()
        if assessment is None:
            raise RuntimeError("Run a read-only RTGS assessment before requesting an action.")
        results: list[RTGSActionResult] = []
        for transaction_id in dict.fromkeys(request.transaction_ids):
            result = self._execute_one(request, transaction_id=transaction_id, requested_by=requested_by)
            results.append(result)
        return results

    def _execute_one(
        self,
        request: RTGSActionRequest,
        *,
        transaction_id: str,
        requested_by: str,
        execution_mode: str = "manual",
        policy_updated_by: str | None = None,
    ) -> RTGSActionResult:
        with self.repository.action_lock(f"rtgs:{transaction_id}"):
            return self._execute_one_unlocked(
                request,
                transaction_id=transaction_id,
                requested_by=requested_by,
                execution_mode=execution_mode,
                policy_updated_by=policy_updated_by,
            )

    def _execute_one_unlocked(
        self,
        request: RTGSActionRequest,
        *,
        transaction_id: str,
        requested_by: str,
        execution_mode: str,
        policy_updated_by: str | None,
    ) -> RTGSActionResult:
        if request.idempotency_key:
            existing = self.repository.get_action(f"{request.idempotency_key}:{transaction_id}")
            if existing:
                return existing
        try:
            RTGSOracleGateway._validate_transaction_id(transaction_id)
            row = self.oracle.get_current_transaction(transaction_id)
            if row is None:
                return self._record(request, transaction_id, requested_by, "NOOP", "Transaction is no longer IN_TRANSIT; settlement may have cleared it.", {}, execution_mode=execution_mode, policy_updated_by=policy_updated_by)
            if str(row.get("transaction_status") or "").upper() != "IN_TRANSIT":
                return self._record(request, transaction_id, requested_by, "NOOP", "Transaction is no longer IN_TRANSIT; settlement may have cleared the case.", {"status": row.get("transaction_status")}, execution_mode=execution_mode, policy_updated_by=policy_updated_by)
            case = make_case(row, datetime.now(timezone.utc))
            if case.age_lane == "OVER_96H" and not request.confirm_over_96h:
                return self._record(request, transaction_id, requested_by, "BLOCKED", "Transactions older than 96 hours require explicit reconciliation confirmation.", {"age_lane": case.age_lane}, execution_mode=execution_mode, policy_updated_by=policy_updated_by)
            if not case.regeneration_ready:
                return self._record(request, transaction_id, requested_by, "BLOCKED", "Regeneration is blocked because no outbound queue instance is linked to this transaction.", {"recommendation": case.recommendation}, execution_mode=execution_mode, policy_updated_by=policy_updated_by)
            message = self.oracle.regenerate(row)
            return self._record(
                request,
                transaction_id,
                requested_by,
                "COMPLETED",
                f"{message} Re-run the database assessment to confirm the current queue state.",
                {"queue_instance_ids": case.queue_instance_ids, "database_recheck_required": True},
                execution_mode=execution_mode,
                policy_updated_by=policy_updated_by,
            )
        except Exception as exc:
            logger.exception("RTGS action failed for %s", transaction_id)
            return self._record(request, transaction_id, requested_by, "FAILED", str(exc), {}, execution_mode=execution_mode, policy_updated_by=policy_updated_by)

    def _record(
        self,
        request: RTGSActionRequest,
        transaction_id: str,
        requested_by: str,
        status: str,
        message: str,
        verification: dict[str, Any],
        *,
        execution_mode: str,
        policy_updated_by: str | None,
    ) -> RTGSActionResult:
        action_verification = {**verification, "execution_mode": execution_mode}
        if policy_updated_by:
            action_verification["policy_updated_by"] = policy_updated_by
        result = RTGSActionResult(action_id=f"rtgs-action-{uuid4()}", action="regenerate", status=status, requested_by=requested_by, transaction_id=transaction_id, message=message, verification=action_verification)
        key = f"{request.idempotency_key}:{transaction_id}" if request.idempotency_key else None
        try:
            self.repository.save_action(result, key, request.reason)
        except Exception:
            logger.exception("Unable to persist RTGS action ledger entry %s", result.action_id)
        audit_logger.log(
            event_type="nexus_rtgs_action",
            user=requested_by,
            details={
                "action_id": result.action_id,
                "transaction_id": transaction_id,
                "action": "regenerate",
                "status": status,
                "reason": request.reason,
                "execution_mode": execution_mode,
                "policy_updated_by": policy_updated_by,
            },
        )
        return result
