from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import nexus as nexus_api
from app.nexus.incident_notifications import NexusIncidentNotificationDispatcher
from app.nexus.models import (
    NexusIncidentNotificationSettings,
    NexusIncidentNotificationSettingsUpdate,
)
from app.nexus.repository import NexusRepository
from app.utils.sentinelops_auth import require_nexus_access


def _incident(status: str = "OPEN", *, ended: bool = False) -> dict[str, object]:
    return {
        "incident_id": str(uuid4()),
        "incident_key": "flow:service_runtime:txn-mobile-ussd",
        "title": "Mobile USSD degradation",
        "status": status,
        "start_time": "2026-09-12T08:00:00Z",
        "end_time": "2026-09-12T08:10:00Z" if ended else None,
        "summary": "Mobile Banking USSD is unavailable.",
        "risk_level": "HIGH",
        "affected_services": ["txn-mobile-ussd"],
        "suspected_root_service": "txn-mobile-ussd",
        "suspected_root_service_name": "Mobile Banking USSD",
        "failure_domain": "service_runtime",
    }


def test_incident_notification_lifecycle_emits_once_per_transition() -> None:
    opened = _incident()

    transitions = NexusRepository.incident_notification_transitions([], [opened])
    assert [item["event_type"] for item in transitions] == ["OPENED"]
    assert NexusRepository.incident_notification_transitions([opened], [opened]) == []

    recovered = {**deepcopy(opened), "status": "AWAITING_VERDICT", "end_time": "2026-09-12T08:10:00Z"}
    transitions = NexusRepository.incident_notification_transitions([opened], [recovered])
    assert [item["event_type"] for item in transitions] == ["RECOVERED"]
    assert NexusRepository.incident_notification_transitions([recovered], [recovered]) == []


def test_additional_notification_emails_are_normalized_and_validated() -> None:
    request = NexusIncidentNotificationSettingsUpdate(
        additional_email_recipients=[" Owner@Example.com ", "owner@example.com", "ops@example.com"]
    )
    assert request.additional_email_recipients == ["owner@example.com", "ops@example.com"]

    with pytest.raises(ValueError, match="Invalid additional notification email"):
        NexusIncidentNotificationSettingsUpdate(additional_email_recipients=["not-an-email"])


def test_current_shift_lookup_is_safe_when_roster_tables_are_not_deployed() -> None:
    class MissingRosterCursor:
        def __init__(self) -> None:
            self.execute_count = 0

        def execute(self, _query, _params=None):
            self.execute_count += 1
            return self

        @staticmethod
        def fetchone():
            return {
                "participants_ready": False,
                "instances_ready": False,
                "users_ready": False,
            }

    cursor = MissingRosterCursor()

    contacts = NexusRepository._current_shift_contacts_with_cursor(
        cursor,
        datetime(2026, 9, 12, 8, tzinfo=timezone.utc),
    )

    assert contacts == []
    assert cursor.execute_count == 1


@pytest.mark.parametrize(
    ("role", "expected_recipients"),
    [
        ("admin", ["owner@example.com"]),
        ("operator", []),
    ],
)
def test_notification_settings_addresses_are_visible_only_to_admins(role, expected_recipients) -> None:
    notification_settings = NexusIncidentNotificationSettings(
        additional_email_recipients=["owner@example.com"],
        additional_email_recipient_count=1,
    )
    nexus_service = SimpleNamespace(
        get_incident_notification_settings=lambda: notification_settings,
    )
    app = FastAPI()
    app.state.services = SimpleNamespace(nexus=nexus_service)
    app.dependency_overrides[require_nexus_access] = lambda: {
        "username": "operator",
        "role": role,
    }
    app.include_router(nexus_api.router, prefix="/api/v1")

    response = TestClient(app).get("/api/v1/nexus/notifications/settings")

    assert response.status_code == 200
    assert response.json()["additional_email_recipients"] == expected_recipients
    assert response.json()["additional_email_recipient_count"] == 1


class _DispatcherRepository:
    def __init__(self, *, enabled: bool = True) -> None:
        self.settings = NexusIncidentNotificationSettings(
            enabled=enabled,
            notify_current_shift=True,
            in_app_enabled=True,
            email_enabled=True,
            notify_on_recovery=True,
            additional_email_recipients=["owner@example.com"],
            smtp_configured=True,
        )
        self.completed: list[dict[str, object]] = []
        self.retried: list[dict[str, object]] = []
        self.in_app_calls = 0

    def get_incident_notification_settings(self) -> NexusIncidentNotificationSettings:
        return self.settings

    def list_current_shift_participant_contacts(self, _reference_time: datetime):
        return [{"id": str(uuid4()), "email": "shift@example.com", "recipient_name": "Shift Operator"}]

    def create_incident_in_app_notifications(self, _delivery, contacts) -> int:
        self.in_app_calls += 1
        return len(contacts)

    def complete_incident_notification_delivery(self, delivery_key: str, **kwargs) -> None:
        self.completed.append({"delivery_key": delivery_key, **kwargs})

    def retry_incident_notification_delivery(self, delivery_key: str, **kwargs) -> None:
        self.retried.append({"delivery_key": delivery_key, **kwargs})


def _delivery(*, attempts: int = 1) -> dict[str, object]:
    incident = _incident()
    return {
        "delivery_key": f"opened:{incident['incident_id']}:{incident['start_time']}",
        "incident_id": incident["incident_id"],
        "incident_started_at": datetime(2026, 9, 12, 8, tzinfo=timezone.utc),
        "event_type": "OPENED",
        "status": "PROCESSING",
        "attempts": attempts,
        "delivered_count": 0,
        "in_app_delivered": False,
        "email_delivered": False,
        "payload": {"event_type": "OPENED", "incident": incident},
    }


def test_dispatcher_delivers_shift_and_additional_recipients_without_blocking_ingest() -> None:
    repository = _DispatcherRepository()
    email_calls: list[dict[str, object]] = []
    dispatcher = NexusIncidentNotificationDispatcher(
        repository,  # type: ignore[arg-type]
        email_sender=lambda **kwargs: email_calls.append(kwargs),
    )

    dispatcher._process_delivery(_delivery())

    assert repository.in_app_calls == 1
    assert len(email_calls) == 1
    assert email_calls[0]["recipients"] == ["shift@example.com", "owner@example.com"]
    assert repository.completed[0]["status_value"] == "SENT"
    assert repository.completed[0]["recipient_count"] == 3
    assert repository.retried == []


def test_dispatcher_retries_only_the_failed_channel() -> None:
    repository = _DispatcherRepository()

    def fail_email(**_kwargs) -> None:
        raise RuntimeError("relay unavailable")

    dispatcher = NexusIncidentNotificationDispatcher(repository, email_sender=fail_email)  # type: ignore[arg-type]
    dispatcher._process_delivery(_delivery())

    assert repository.in_app_calls == 1
    assert repository.retried[0]["in_app_delivered"] is True
    assert repository.retried[0]["email_delivered"] is False
    assert repository.completed == []


def test_dispatcher_failure_preserves_previously_delivered_channel_state() -> None:
    repository = _DispatcherRepository()
    dispatcher = NexusIncidentNotificationDispatcher(repository, email_sender=lambda **_kwargs: None)  # type: ignore[arg-type]
    delivery = {
        **_delivery(attempts=2),
        "recipient_count": 3,
        "delivered_count": 1,
        "in_app_delivered": True,
        "email_delivered": False,
    }

    dispatcher._record_delivery_failure(
        delivery,
        RuntimeError("unexpected worker failure"),
        int(delivery["recipient_count"]),
        int(delivery["delivered_count"]),
        bool(delivery["in_app_delivered"]),
        bool(delivery["email_delivered"]),
    )

    assert repository.retried[0]["recipient_count"] == 3
    assert repository.retried[0]["delivered_count"] == 1
    assert repository.retried[0]["in_app_delivered"] is True
    assert repository.retried[0]["email_delivered"] is False


def test_dispatch_loop_survives_when_failure_state_cannot_be_persisted() -> None:
    class UnavailableRepository:
        def __init__(self) -> None:
            self.claim_count = 0

        def claim_next_incident_notification(self, _worker_id):
            self.claim_count += 1
            if self.claim_count == 1:
                return _delivery()
            dispatcher._stop_event.set()
            return None

        @staticmethod
        def retry_incident_notification_delivery(_delivery_key, **_kwargs):
            raise RuntimeError("database unavailable")

    repository = UnavailableRepository()
    dispatcher = NexusIncidentNotificationDispatcher(repository)  # type: ignore[arg-type]
    dispatcher.IDLE_POLL_SECONDS = 0

    def fail_processing(_delivery_payload) -> None:
        raise RuntimeError("delivery failed")

    dispatcher._process_delivery = fail_processing  # type: ignore[method-assign]
    dispatcher._run()

    assert repository.claim_count == 2


def test_dispatcher_suppresses_delivery_when_admin_switch_is_off() -> None:
    repository = _DispatcherRepository(enabled=False)
    dispatcher = NexusIncidentNotificationDispatcher(repository, email_sender=lambda **_kwargs: None)  # type: ignore[arg-type]

    dispatcher._process_delivery(_delivery())

    assert repository.completed[0]["status_value"] == "SUPPRESSED"
    assert repository.in_app_calls == 0
