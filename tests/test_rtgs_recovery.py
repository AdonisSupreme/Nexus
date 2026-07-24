from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest

from app.nexus import rtgs as rtgs_module
from app.nexus.models import RTGSActionRequest, RTGSAutoRegenerationPolicy
from app.nexus.rtgs import (
    RTGSRecoveryService,
    _normalize_stored_assessment,
    _translate_auto_policy_storage_error,
    make_case,
)


def _row(*, queue_instance_id: str | None = "queue-001", entry_date: datetime | None = None) -> dict[str, object]:
    return {
        "transaction_id": "AF26198000000065",
        "transaction_status": "IN_TRANSIT",
        "entry_date": entry_date or datetime.now(timezone.utc) - timedelta(hours=8),
        "branch_code": "1025",
        "entry_sequence": "2",
        "message_type": "ZWRTGCO",
        "queue_instance_ids": [queue_instance_id] if queue_instance_id else [],
    }


def test_make_case_uses_database_queue_context_for_regeneration():
    case = make_case(_row(), datetime.now(timezone.utc))

    assert case.regeneration_ready is True
    assert case.recommendation == "REGENERATE"
    assert case.queue_instance_ids == ["queue-001"]
    assert not hasattr(case, "files")


def test_make_case_blocks_rows_without_queue_context():
    case = make_case(_row(queue_instance_id=None), datetime.now(timezone.utc))

    assert case.regeneration_ready is False
    assert case.recommendation == "QUEUE_CONTEXT_MISSING"
    assert any("queue instance" in warning for warning in case.warnings)


def test_auto_policy_storage_reports_stale_schema():
    with pytest.raises(RuntimeError, match="storage is out of date"):
        with _translate_auto_policy_storage_error():
            raise rtgs_module.psycopg.errors.UndefinedColumn("last_run_at")


def test_auto_policy_storage_reports_missing_role_grants():
    with pytest.raises(RuntimeError, match="database role cannot access"):
        with _translate_auto_policy_storage_error():
            raise rtgs_module.psycopg.errors.InsufficientPrivilege("permission denied")


def test_stored_legacy_assessment_is_readable_without_peer_contract():
    payload = {
        "assessment_id": "legacy-assessment",
        "trigger": "manual",
        "assessed_at": datetime.now(timezone.utc).isoformat(),
        "transaction_count": 1,
        "cases": [{
            **_row(),
            "entry_date": _row()["entry_date"].isoformat(),
            "age_hours": 8,
            "age_lane": "0_24H",
            "recommendation": "ASSESSMENT_INCOMPLETE",
            "file_state": "NOT_FOUND",
            "files": [],
        }],
        "status": "COMPLETED",
    }

    normalized = _normalize_stored_assessment(payload)

    assert normalized["cases"][0]["recommendation"] == "REGENERATE"
    assert normalized["cases"][0]["regeneration_ready"] is True
    assert "files" not in normalized["cases"][0]
    assert "file_state" not in normalized["cases"][0]


class InMemoryRTGSRepository:
    def __init__(self) -> None:
        self.assessment = None
        self.actions = []
        self.policy = RTGSAutoRegenerationPolicy()
        self.policy_audit = []

    def save_assessment(self, assessment):
        self.assessment = assessment

    def latest_assessment(self):
        return self.assessment

    def get_action(self, key):
        return None

    def save_action(self, result, idempotency_key, reason):
        self.actions.append((result, idempotency_key, reason))

    def completed_automatic_transaction_ids(self, transaction_ids):
        candidates = set(transaction_ids)
        return {
            result.transaction_id
            for result, _, _ in self.actions
            if result.transaction_id in candidates
            and result.status == "COMPLETED"
            and result.verification.get("execution_mode") == "automatic"
        }

    def get_auto_policy(self):
        return self.policy

    def set_auto_policy(self, *, enabled, changed_by):
        previous_enabled = self.policy.enabled
        self.policy = self.policy.model_copy(
            update={
                "enabled": enabled,
                "updated_by": changed_by,
                "updated_at": datetime.now(timezone.utc),
            }
        )
        if previous_enabled != enabled:
            self.policy_audit.insert(
                0,
                {
                    "previous_enabled": previous_enabled,
                    "enabled": enabled,
                    "changed_by": changed_by,
                },
            )
        return self.policy

    def list_auto_policy_audit(self, limit):
        return self.policy_audit[:limit]

    def record_auto_run(self, *, attempted, completed, status):
        self.policy = self.policy.model_copy(
            update={
                "last_run_at": datetime.now(timezone.utc),
                "last_attempted_count": attempted,
                "last_completed_count": completed,
                "last_run_status": status,
            }
        )
        return self.policy

    @contextmanager
    def action_lock(self, key):
        yield


class DatabaseOnlyOracle:
    def __init__(self) -> None:
        self.rows = [_row()]
        self.regenerations = []

    def list_current_transactions(self):
        return self.rows

    def get_current_transaction(self, transaction_id):
        return next((row for row in self.rows if row["transaction_id"] == transaction_id), None)

    def regenerate(self, row):
        self.regenerations.append(row["transaction_id"])
        return "Oracle regeneration package completed."


def test_assessment_and_regeneration_use_only_database_gateway(monkeypatch):
    repository = InMemoryRTGSRepository()
    oracle = DatabaseOnlyOracle()
    monkeypatch.setattr(rtgs_module.audit_logger, "log", lambda **kwargs: None)
    service = RTGSRecoveryService(repository=repository, oracle=oracle)

    assessment = service.assess(trigger="manual", requested_by="operator")
    result = service.execute(
        RTGSActionRequest(
            transaction_ids=["AF26198000000065"],
            reason="Requeue after operator review",
            idempotency_key="rtgs-regenerate-test",
            confirm_over_96h=False,
        ),
        requested_by="operator",
    )[0]

    assert assessment.transaction_count == 1
    assert assessment.cases[0].regeneration_ready is True
    assert result.action == "regenerate"
    assert result.status == "COMPLETED"
    assert oracle.regenerations == ["AF26198000000065"]
    assert not hasattr(assessment.cases[0], "files")
    assert not hasattr(result, "evidence")


def test_auto_regeneration_only_processes_latest_five_days_once(monkeypatch):
    repository = InMemoryRTGSRepository()
    repository.policy = repository.policy.model_copy(
        update={"enabled": True, "updated_by": "admin-user"}
    )
    oracle = DatabaseOnlyOracle()
    recent = _row(entry_date=datetime.now(timezone.utc) - timedelta(days=2))
    older = {
        **_row(entry_date=datetime.now(timezone.utc) - timedelta(days=6)),
        "transaction_id": "AF26198000000066",
        "queue_instance_ids": ["queue-002"],
    }
    oracle.rows = [recent, older]
    monkeypatch.setattr(rtgs_module.audit_logger, "log", lambda **kwargs: None)
    service = RTGSRecoveryService(repository=repository, oracle=oracle)

    assessment = service.assess(trigger="scheduled", requested_by=None)
    first_results = service.run_auto_regeneration(assessment)
    second_results = service.run_auto_regeneration(assessment)

    assert [result.transaction_id for result in first_results] == [recent["transaction_id"]]
    assert first_results[0].verification["execution_mode"] == "automatic"
    assert first_results[0].verification["policy_updated_by"] == "admin-user"
    assert second_results == []
    assert oracle.regenerations == [recent["transaction_id"]]
    assert repository.policy.last_run_status == "COMPLETED"


def test_auto_regeneration_policy_toggle_is_audited(monkeypatch):
    repository = InMemoryRTGSRepository()
    monkeypatch.setattr(rtgs_module.audit_logger, "log", lambda **kwargs: None)
    service = RTGSRecoveryService(repository=repository, oracle=DatabaseOnlyOracle())

    enabled = service.set_auto_policy(enabled=True, changed_by="admin-user")
    unchanged = service.set_auto_policy(enabled=True, changed_by="admin-user")
    disabled = service.set_auto_policy(enabled=False, changed_by="second-admin")

    assert enabled.enabled is True
    assert unchanged.enabled is True
    assert disabled.enabled is False
    assert repository.policy_audit == [
        {"previous_enabled": True, "enabled": False, "changed_by": "second-admin"},
        {"previous_enabled": False, "enabled": True, "changed_by": "admin-user"},
    ]
