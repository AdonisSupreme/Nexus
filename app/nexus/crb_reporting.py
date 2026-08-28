"""Read-only LMS CRB report extraction and same-day artifact custody."""

from __future__ import annotations

import asyncio
import csv
import hashlib
import os
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime, time, timezone
from pathlib import Path
from typing import Any, Iterator, Literal
from uuid import uuid4
from zoneinfo import ZoneInfo

import psycopg
from psycopg.rows import dict_row

from app.config.settings import settings
from app.utils.audit import audit_logger
from app.utils.logging import get_logger


logger = get_logger(__name__)
CRB_MIGRATION = "2026_14_add_nexus_crb_reporting.sql"
CRB_LOCK_KEY = "sentinelops:nexus:crb-extraction"


@dataclass(frozen=True)
class CRBReportSpec:
    key: str
    label: str
    view_name: str
    fields: tuple[str, ...]


CRB_REPORTS = (
    CRBReportSpec(
        key="CONTRACT_DATA",
        label="Contract data",
        view_name="VW_CONTRACT_DATA",
        fields=(
            "SUBSCRIBERCODE", "REPORTINGDATE", "CONTRACTCODE", "BRANCH", "PHASEOFCONTRACT",
            "CONTRACTSTATUS", "TRANSFERSTATUS", "TYPEOFCONTRACT", "CREDITCLASSIFICATION",
            "PURPOSEOFFINANCING", "CURRENCYOFCONTRACT", "METHODOFPAYMENT", "FACILITYLIMIT",
            "PRINCIPALDRAWN", "INSTALLMENTAMOUNT", "NUMBEROFINSTALLMENTS", "OUTSTANDINGAMOUNT",
            "PASTDUEAMOUNT", "PASTDUEDAYS", "NUMBEROFDUEINSTALLMENTS", "DATEOFLASTPAYMENTRECEIVED",
            "TOTALMONTHLYPAYMENT", "PAYMENTPERIODICITY", "STARTDATE", "RESTRUCTURINGDATE",
            "RESTRUCTURINGREASON", "EXPECTEDENDDATE", "REALENDDATE", "NEGATIVESTATUSOFCONTRACT",
            "DEFAULTDATE", "BUSINESSDATE", "SNO",
        ),
    ),
    CRBReportSpec(
        key="INDIVIDUAL_DETAILS",
        label="Individual client details",
        view_name="LMS_INDCLT_DETAILS",
        fields=(
            "BUSINESSDATE", "SNO", "CONTRACTCODE", "CUSTOMERCODE", "SURNAME", "MAIDENNAME",
            "FIRSTNAME", "MIDDLENAMES", "FULLNAME", "SPOUSENAME", "NUMBEROFDEPENDANTS",
            "CLASSIFICATIONOFINDIVIDUAL", "GENDER", "DATEOFBIRTH", "COUNTRYOFBIRTH",
            "DISTRICTOFBIRTH", "MARITALSTATUS", "RESIDENCY", "CITIZENSHIP", "NATIONALITY",
            "PROFESSION", "EMPLOYERNAME", "EDUCATION", "BUSINESSNAME", "ESTABLISHMENTDATE",
            "GROSSINCOME", "AVERAGEMONTHLYEXPENDITURES", "NEGATIVESTATUSOFINDIVIDUAL",
            "NATIONALID", "NATIONALIDISSUEDATE", "NATIONALIDEXPIRATIONDATE",
            "NATIONALIDPLACEOFISSUE", "PASSPORTNUMBER", "PASSPORTISSUEDATE",
            "PASSPORTEXPIRATIONDATE", "PASSPORTPLACEOFISSUE", "PASSPORTISSUERCOUNTRY",
            "PREVIOUSPASSPORTNUMBER", "DRIVINGLICENSENUMBER", "DRIVINGLICENSEISSUEDATE",
            "DRIVINGLICENSEEXPIRATIONDATE", "DRIVINGLICENSEPLACEOFISSUE", "BUSINESSLICENCENUMBER",
            "MAINADDRESS", "MAINADDRESSCITYORDISTRICT", "MAINADDRESSCOUNTRY",
            "MAINADDRESSADDRESSLINE", "SECONDARYADDRESS", "SECONDARYADDRESSCITYORDISTRICT",
            "SECONDARYADDRESSCOUNTRY", "SECONDARYADDRESSADDRESSLINE", "CELLULARPHONE",
            "FIXEDLINE", "EMAIL", "FAX", "WORKPHONE", "CURRENCYOFCONTRACT",
        ),
    ),
)


def _plain(value: Any) -> Any:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


class CRBStorageError(RuntimeError):
    pass


class CRBReportRepository:
    def __init__(self) -> None:
        self._dsn = settings.nexus_database_dsn

    @contextmanager
    def _connection(self):
        if not self._dsn:
            raise CRBStorageError("CRB reporting requires the shared SentinelOps database.")
        try:
            with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
                yield connection
        except (psycopg.errors.UndefinedTable, psycopg.errors.UndefinedColumn) as exc:
            raise CRBStorageError(
                f"CRB reporting storage is not initialized. Apply {CRB_MIGRATION} and restart Nexus."
            ) from exc

    def create_run(
        self,
        *,
        trigger: Literal["SCHEDULED", "MANUAL"],
        requested_by: str,
        run_day: date,
    ) -> dict[str, Any]:
        run_id = f"nexus-crb-run-{uuid4()}"
        try:
            with self._connection() as connection:
                with connection.cursor() as cursor:
                    row = cursor.execute(
                        """
                        INSERT INTO nexus_crb_report_run (
                            run_id, run_day, trigger, status, requested_by
                        ) VALUES (%s, %s, %s, 'QUEUED', %s)
                        RETURNING *
                        """,
                        (run_id, run_day, trigger, requested_by),
                    ).fetchone()
                connection.commit()
            return _plain(dict(row))
        except psycopg.errors.UniqueViolation as exc:
            raise ValueError("The scheduled CRB extraction for this business day is already recorded.") from exc

    def begin_run(self, run_id: str) -> dict[str, Any]:
        with self._connection() as connection:
            with connection.cursor() as cursor:
                row = cursor.execute(
                    """
                    UPDATE nexus_crb_report_run
                    SET status = 'RUNNING', started_at = now(), current_report = NULL, error_message = NULL
                    WHERE run_id = %s AND status = 'QUEUED'
                    RETURNING *
                    """,
                    (run_id,),
                ).fetchone()
            connection.commit()
        if not row:
            raise ValueError("This CRB run has already started or no longer exists.")
        return _plain(dict(row))

    def set_current_report(self, run_id: str, view_name: str) -> None:
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE nexus_crb_report_run SET current_report = %s WHERE run_id = %s",
                    (view_name, run_id),
                )
            connection.commit()

    def save_artifact(self, run_id: str, spec: CRBReportSpec, metadata: dict[str, Any]) -> dict[str, Any]:
        artifact_id = f"nexus-crb-artifact-{uuid4()}"
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE nexus_crb_report_artifact
                    SET status = 'REPLACED'
                    WHERE report_key = %s AND status = 'GENERATED'
                    """,
                    (spec.key,),
                )
                row = cursor.execute(
                    """
                    INSERT INTO nexus_crb_report_artifact (
                        artifact_id, run_id, report_key, view_name, filename, storage_path,
                        status, row_count, byte_size, sha256, generated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, 'GENERATED', %s, %s, %s, now())
                    RETURNING *
                    """,
                    (
                        artifact_id,
                        run_id,
                        spec.key,
                        spec.view_name,
                        metadata["filename"],
                        metadata["storage_path"],
                        metadata["row_count"],
                        metadata["byte_size"],
                        metadata["sha256"],
                    ),
                ).fetchone()
            connection.commit()
        return _plain(dict(row))

    def finish_run(self, run_id: str, *, status: str, error: str | None = None) -> dict[str, Any]:
        with self._connection() as connection:
            with connection.cursor() as cursor:
                row = cursor.execute(
                    """
                    UPDATE nexus_crb_report_run
                    SET status = %s, completed_at = now(), current_report = NULL, error_message = %s
                    WHERE run_id = %s
                    RETURNING *
                    """,
                    (status, error[:3000] if error else None, run_id),
                ).fetchone()
            connection.commit()
        if not row:
            raise LookupError("CRB extraction run not found.")
        return self.get_run(run_id)

    def get_run(self, run_id: str) -> dict[str, Any]:
        with self._connection() as connection:
            with connection.cursor() as cursor:
                run = cursor.execute(
                    "SELECT * FROM nexus_crb_report_run WHERE run_id = %s",
                    (run_id,),
                ).fetchone()
                if not run:
                    raise LookupError("CRB extraction run not found.")
                artifacts = cursor.execute(
                    "SELECT * FROM nexus_crb_report_artifact WHERE run_id = %s ORDER BY report_key",
                    (run_id,),
                ).fetchall()
        return {**_plain(dict(run)), "artifacts": [_plain(dict(row)) for row in artifacts]}

    def overview(self, *, today: date, next_schedule_at: datetime) -> dict[str, Any]:
        with self._connection() as connection:
            with connection.cursor() as cursor:
                runs = cursor.execute(
                    "SELECT * FROM nexus_crb_report_run ORDER BY created_at DESC LIMIT 20"
                ).fetchall()
                current = cursor.execute(
                    """
                    SELECT * FROM nexus_crb_report_artifact
                    WHERE status = 'GENERATED'
                    ORDER BY report_key
                    """
                ).fetchall()
        latest = _plain(dict(runs[0])) if runs else None
        return {
            "business_day": today.isoformat(),
            "schedule_time": settings.NEXUS_CRB_SCHEDULE_TIME,
            "timezone": settings.NEXUS_CRB_TIMEZONE,
            "next_schedule_at": next_schedule_at.isoformat(),
            "latest_run": latest,
            "current_artifacts": [_plain(dict(row)) for row in current],
            "runs": [_plain(dict(row)) for row in runs],
            "reports": [
                {
                    "report_key": spec.key,
                    "label": spec.label,
                    "view_name": spec.view_name,
                    "field_count": len(spec.fields),
                }
                for spec in CRB_REPORTS
            ],
        }

    def get_artifact(self, artifact_id: str) -> dict[str, Any]:
        with self._connection() as connection:
            with connection.cursor() as cursor:
                row = cursor.execute(
                    "SELECT * FROM nexus_crb_report_artifact WHERE artifact_id = %s",
                    (artifact_id,),
                ).fetchone()
        if not row:
            raise LookupError("CRB report artifact not found.")
        return _plain(dict(row))

    def scheduled_run_exists(self, run_day: date) -> bool:
        with self._connection() as connection:
            with connection.cursor() as cursor:
                row = cursor.execute(
                    """
                    SELECT 1 FROM nexus_crb_report_run
                    WHERE run_day = %s AND trigger = 'SCHEDULED'
                    LIMIT 1
                    """,
                    (run_day,),
                ).fetchone()
        return bool(row)

    def claim_cleanup(self, run_day: date) -> bool:
        with self._connection() as connection:
            with connection.cursor() as cursor:
                row = cursor.execute(
                    """
                    SELECT last_cleanup_day FROM nexus_crb_maintenance
                    WHERE maintenance_key = 'daily-retention'
                    FOR UPDATE
                    """
                ).fetchone()
                if not row:
                    raise CRBStorageError(
                        f"CRB reporting storage is incomplete. Apply {CRB_MIGRATION} and restart Nexus."
                    )
                if row["last_cleanup_day"] == run_day:
                    return False
                cursor.execute(
                    """
                    UPDATE nexus_crb_maintenance
                    SET last_cleanup_day = %s, updated_at = now()
                    WHERE maintenance_key = 'daily-retention'
                    """,
                    (run_day,),
                )
            connection.commit()
        return True

    def mark_expired_artifacts(self, today: date) -> list[str]:
        with self._connection() as connection:
            with connection.cursor() as cursor:
                rows = cursor.execute(
                    """
                    UPDATE nexus_crb_report_artifact artifact
                    SET status = 'PURGED', purged_at = now()
                    FROM nexus_crb_report_run run
                    WHERE artifact.run_id = run.run_id
                      AND artifact.status = 'GENERATED'
                      AND run.run_day < %s
                    RETURNING artifact.storage_path
                    """,
                    (today,),
                ).fetchall()
            connection.commit()
        return [str(row["storage_path"]) for row in rows]

    @contextmanager
    def extraction_lock(self) -> Iterator[None]:
        if not self._dsn:
            raise CRBStorageError("CRB reporting requires the shared SentinelOps database.")
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            locked = connection.execute(
                "SELECT pg_try_advisory_lock(hashtext(%s)) AS locked",
                (CRB_LOCK_KEY,),
            ).fetchone()["locked"]
            if not locked:
                raise ValueError("Another CRB extraction is already running.")
            try:
                yield
            finally:
                connection.execute("SELECT pg_advisory_unlock(hashtext(%s))", (CRB_LOCK_KEY,))


class LMSOracleGateway:
    @property
    def configured(self) -> bool:
        return bool(
            settings.LMS_ORACLE_USER
            and settings.LMS_ORACLE_PASSWORD
            and (
                settings.LMS_ORACLE_DSN
                or (
                    settings.LMS_ORACLE_HOST
                    and (settings.LMS_ORACLE_SID or settings.LMS_ORACLE_SERVICE_NAME)
                )
            )
        )

    @contextmanager
    def connection(self):
        if not self.configured:
            raise RuntimeError(
                "LMS Oracle is not configured. Set LMS_ORACLE_USER, LMS_ORACLE_PASSWORD, and either "
                "LMS_ORACLE_DSN or LMS_ORACLE_HOST plus LMS_ORACLE_SID/LMS_ORACLE_SERVICE_NAME."
            )
        try:
            import oracledb
        except ImportError as exc:
            raise RuntimeError("The oracledb package is required for CRB extraction.") from exc
        dsn = settings.LMS_ORACLE_DSN
        if not dsn:
            if settings.LMS_ORACLE_SID:
                dsn = oracledb.makedsn(
                    settings.LMS_ORACLE_HOST,
                    settings.LMS_ORACLE_PORT,
                    sid=settings.LMS_ORACLE_SID,
                )
            else:
                dsn = oracledb.makedsn(
                    settings.LMS_ORACLE_HOST,
                    settings.LMS_ORACLE_PORT,
                    service_name=settings.LMS_ORACLE_SERVICE_NAME,
                )
        connection = oracledb.connect(
            user=settings.LMS_ORACLE_USER,
            password=settings.LMS_ORACLE_PASSWORD.get_secret_value(),
            dsn=dsn,
            config_dir=settings.LMS_ORACLE_CONFIG_DIR or None,
            tcp_connect_timeout=settings.ORACLE_CONNECT_TIMEOUT_SECONDS,
        )
        try:
            connection.call_timeout = max(30_000, settings.ORACLE_CONNECT_TIMEOUT_SECONDS * 1000)
            yield connection
        finally:
            connection.close()


class CRBReportingService:
    def __init__(
        self,
        repository: CRBReportRepository | None = None,
        oracle: LMSOracleGateway | None = None,
    ) -> None:
        self.repository = repository or CRBReportRepository()
        self.oracle = oracle or LMSOracleGateway()
        self.report_dir = settings.NEXUS_CRB_REPORT_DIR.resolve()
        self.report_dir.mkdir(parents=True, exist_ok=True)

    @property
    def zone(self) -> ZoneInfo:
        return ZoneInfo(settings.NEXUS_CRB_TIMEZONE)

    def _schedule_time(self) -> time:
        try:
            hour, minute = (int(value) for value in settings.NEXUS_CRB_SCHEDULE_TIME.split(":", 1))
            return time(hour, minute)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("NEXUS_CRB_SCHEDULE_TIME must use HH:MM 24-hour format.") from exc

    def local_now(self) -> datetime:
        return datetime.now(timezone.utc).astimezone(self.zone)

    def next_schedule_at(self, now: datetime | None = None) -> datetime:
        local = (now or self.local_now()).astimezone(self.zone)
        scheduled = datetime.combine(local.date(), self._schedule_time(), tzinfo=self.zone)
        if local >= scheduled:
            from datetime import timedelta

            scheduled += timedelta(days=1)
        return scheduled

    def overview(self) -> dict[str, Any]:
        now = self.local_now()
        return {
            **self.repository.overview(today=now.date(), next_schedule_at=self.next_schedule_at(now)),
            "oracle_configured": self.oracle.configured,
            "retention": "CURRENT_DAY",
        }

    def prepare_run(self, *, trigger: Literal["SCHEDULED", "MANUAL"], requested_by: str) -> dict[str, Any]:
        return self.repository.create_run(
            trigger=trigger,
            requested_by=requested_by,
            run_day=self.local_now().date(),
        )

    def execute_run(self, run_id: str) -> dict[str, Any]:
        generated = 0
        current_view = None
        try:
            with self.repository.extraction_lock():
                run = self.repository.begin_run(run_id)
                with self.oracle.connection() as connection:
                    for spec in CRB_REPORTS:
                        current_view = spec.view_name
                        self.repository.set_current_report(run_id, spec.view_name)
                        metadata = self._extract_one(connection, spec)
                        self.repository.save_artifact(run_id, spec, metadata)
                        generated += 1
                result = self.repository.finish_run(run_id, status="COMPLETED")
            audit_logger.log(
                event_type="nexus_crb_extraction",
                user=str(run.get("requested_by") or "crb-scheduler"),
                details={"run_id": run_id, "trigger": run.get("trigger"), "reports": generated},
                success=True,
            )
            return result
        except Exception as exc:
            logger.exception("CRB extraction failed for %s at %s", run_id, current_view or "startup")
            try:
                result = self.repository.finish_run(
                    run_id,
                    status="PARTIAL" if generated else "FAILED",
                    error=f"{current_view or 'Extraction'}: {exc}",
                )
            except Exception:
                logger.exception("Unable to persist failed CRB run %s", run_id)
                raise
            audit_logger.log(
                event_type="nexus_crb_extraction",
                user=str(result.get("requested_by") or "crb-scheduler"),
                details={"run_id": run_id, "reports": generated, "error": str(exc)},
                success=False,
            )
            return result

    def _extract_one(self, connection: Any, spec: CRBReportSpec) -> dict[str, Any]:
        filename = f"{spec.view_name}.csv"
        target = (self.report_dir / filename).resolve()
        if target.parent != self.report_dir:
            raise RuntimeError("CRB artifact path escaped its configured report directory.")
        temporary = self.report_dir / f".{filename}.{uuid4().hex}.tmp"
        row_count = 0
        digest = hashlib.sha256()
        query = f"SELECT {', '.join(spec.fields)} FROM {spec.view_name}"
        try:
            with connection.cursor() as cursor, temporary.open("w", encoding="utf-8", newline="") as handle:
                cursor.arraysize = max(100, settings.NEXUS_CRB_FETCH_SIZE)
                cursor.prefetchrows = max(100, settings.NEXUS_CRB_FETCH_SIZE)
                cursor.execute(query)
                writer = csv.writer(handle, lineterminator="\n")
                writer.writerow(spec.fields)
                while True:
                    rows = cursor.fetchmany(settings.NEXUS_CRB_FETCH_SIZE)
                    if not rows:
                        break
                    writer.writerows(
                        tuple("" if value is None else str(value) for value in row)
                        for row in rows
                    )
                    row_count += len(rows)
                handle.flush()
                os.fsync(handle.fileno())
            with temporary.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
        return {
            "filename": filename,
            "storage_path": str(target),
            "row_count": row_count,
            "byte_size": target.stat().st_size,
            "sha256": digest.hexdigest(),
        }

    def artifact_path(self, artifact_id: str) -> tuple[Path, dict[str, Any]]:
        artifact = self.repository.get_artifact(artifact_id)
        if artifact["status"] != "GENERATED":
            raise ValueError("This CRB artifact is no longer retained for download.")
        path = Path(str(artifact["storage_path"])).resolve()
        if path.parent != self.report_dir or not path.is_file():
            raise LookupError("The CRB artifact file is no longer available.")
        return path, artifact

    def purge_expired(self) -> int:
        today = self.local_now().date()
        if not self.repository.claim_cleanup(today):
            return 0
        paths = self.repository.mark_expired_artifacts(today)
        removed = 0
        for raw_path in paths:
            path = Path(raw_path).resolve()
            if path.parent != self.report_dir:
                logger.error("Refusing to purge CRB artifact outside %s: %s", self.report_dir, path)
                continue
            if path.exists():
                path.unlink()
                removed += 1
        return removed


class CRBReportingScheduler:
    def __init__(self, service: CRBReportingService) -> None:
        self.service = service
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._run_lock = threading.Lock()

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        await asyncio.to_thread(self.service.purge_expired)
        self._stop.clear()
        self._task = asyncio.create_task(self._run(), name="sentinelops-crb-reporting-scheduler")

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            await self._task
            self._task = None

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.to_thread(self._tick)
            except Exception:
                logger.exception("CRB scheduler tick failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=30)
            except asyncio.TimeoutError:
                continue

    def _tick(self) -> None:
        self.service.purge_expired()
        now = self.service.local_now()
        if now.time().replace(tzinfo=None) < self.service._schedule_time():
            return
        if self.service.repository.scheduled_run_exists(now.date()):
            return
        with self._run_lock:
            if self.service.repository.scheduled_run_exists(now.date()):
                return
            run = self.service.prepare_run(trigger="SCHEDULED", requested_by="crb-scheduler")
            self.service.execute_run(run["run_id"])
