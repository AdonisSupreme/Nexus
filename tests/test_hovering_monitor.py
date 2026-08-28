from datetime import datetime
from unittest.mock import Mock
from zoneinfo import ZoneInfo

import httpx
import pytest

from app.nexus.hovering_monitor import (
    HoveringMonitorService,
    HoveringQueueGateway,
    RobotPasswordEncryptor,
    active_seconds_between,
    derive_movement,
)


ZONE = ZoneInfo("Africa/Harare")
WINDOW_START = datetime.strptime("03:00", "%H:%M").time()
WEEKDAY_END = datetime.strptime("15:00", "%H:%M").time()
WEEKEND_END = datetime.strptime("09:00", "%H:%M").time()


def test_active_seconds_exclude_the_bot_pause_window():
    started = datetime(2026, 8, 20, 14, 0, tzinfo=ZONE)
    ended = datetime(2026, 8, 21, 4, 0, tzinfo=ZONE)

    seconds = active_seconds_between(
        started,
        ended,
        zone=ZONE,
        window_start=WINDOW_START,
        window_end=WEEKDAY_END,
        weekend_window_end=WEEKEND_END,
    )

    assert seconds == 2 * 60 * 60


def test_weekend_window_closes_at_nine():
    saturday = datetime(2026, 8, 22, 3, 0, tzinfo=ZONE)
    sunday = datetime(2026, 8, 23, 15, 0, tzinfo=ZONE)

    seconds = active_seconds_between(
        saturday,
        sunday,
        zone=ZONE,
        window_start=WINDOW_START,
        window_end=WEEKDAY_END,
        weekend_window_end=WEEKEND_END,
    )

    assert seconds == 12 * 60 * 60


def test_arrivals_and_processed_work_are_separated_when_queue_is_flat():
    movement = derive_movement(
        [{
            "observed_at": datetime(2026, 8, 21, 9, 0, tzinfo=ZONE),
            "pending_count": 300,
            "created_count": 1000,
        }],
        pending_count=300,
        created_count=1060,
        now=datetime(2026, 8, 21, 10, 0, tzinfo=ZONE),
        zone=ZONE,
        window_start=WINDOW_START,
        window_end=WEEKDAY_END,
        weekend_window_end=WEEKEND_END,
        stall_minutes=15,
    )

    assert movement.posture == "MOVING"
    assert movement.arrived_count == 60
    assert movement.processed_count == 60
    assert movement.net_change == 0
    assert movement.rate_per_hour == 60
    assert movement.arrival_rate_per_hour == 60
    assert movement.net_rate_per_hour == 0


def test_movement_rate_uses_only_active_minutes():
    now = datetime(2026, 8, 21, 10, 0, tzinfo=ZONE)
    movement = derive_movement(
        [{"observed_at": datetime(2026, 8, 21, 9, 0, tzinfo=ZONE), "pending_count": 120, "created_count": 1000}],
        pending_count=60,
        created_count=1000,
        now=now,
        zone=ZONE,
        window_start=WINDOW_START,
        window_end=WEEKDAY_END,
        weekend_window_end=WEEKEND_END,
        stall_minutes=15,
    )

    assert movement.posture == "MOVING"
    assert movement.rate_per_hour == 60
    assert movement.observed_active_minutes == 60


def test_non_decreasing_queue_is_stalled_only_inside_the_bot_window():
    baseline = {"observed_at": datetime(2026, 8, 21, 9, 0, tzinfo=ZONE), "pending_count": 60, "created_count": 1000}
    daytime = derive_movement(
        [baseline],
        pending_count=60,
        created_count=1000,
        now=datetime(2026, 8, 21, 9, 20, tzinfo=ZONE),
        zone=ZONE,
        window_start=WINDOW_START,
        window_end=WEEKDAY_END,
        weekend_window_end=WEEKEND_END,
        stall_minutes=15,
    )
    overnight = derive_movement(
        [baseline],
        pending_count=60,
        created_count=1000,
        now=datetime(2026, 8, 21, 18, 0, tzinfo=ZONE),
        zone=ZONE,
        window_start=WINDOW_START,
        window_end=WEEKDAY_END,
        weekend_window_end=WEEKEND_END,
        stall_minutes=15,
    )

    assert daytime.posture == "STALLED"
    assert overnight.posture == "PAUSED"


def test_recent_rate_does_not_hide_a_queue_that_has_since_stalled():
    now = datetime(2026, 8, 21, 10, 0, tzinfo=ZONE)
    movement = derive_movement(
        [
            {"observed_at": datetime(2026, 8, 21, 9, 0, tzinfo=ZONE), "pending_count": 120, "created_count": 1000},
            {"observed_at": datetime(2026, 8, 21, 9, 10, tzinfo=ZONE), "pending_count": 100, "created_count": 1000},
        ],
        pending_count=100,
        created_count=1000,
        now=now,
        zone=ZONE,
        window_start=WINDOW_START,
        window_end=WEEKDAY_END,
        weekend_window_end=WEEKEND_END,
        stall_minutes=15,
    )

    assert movement.rate_per_hour == 20
    assert movement.last_movement_at == datetime(2026, 8, 21, 9, 10, tzinfo=ZONE)
    assert movement.posture == "STALLED"


def test_overview_exposes_queue_truth_and_calculated_clearance(monkeypatch):
    now = datetime(2026, 8, 21, 10, 0, tzinfo=ZONE)
    repository = Mock()
    repository.get_policy.return_value = {"enabled": True, "last_run_status": "COMPLETED"}
    repository.recent_actions.return_value = []
    repository.policy_audit.return_value = []
    repository.recent_samples.return_value = [
        {"observed_at": datetime(2026, 8, 21, 9, 0, tzinfo=ZONE), "pending_count": 120, "created_count": 1000}
    ]
    gateway = Mock()
    gateway.configured = True
    gateway.counts.return_value = {
        "pending_count": 60,
        "created_count": 1000,
        "overdue_count": 4,
        "due_today_count": 56,
        "future_count": 0,
    }
    service = HoveringMonitorService(repository=repository, gateway=gateway)
    monkeypatch.setattr(service, "local_now", lambda: now)

    overview = service.overview()

    assert overview["counts"]["pending_count"] == 60
    assert overview["movement"]["posture"] == "MOVING"
    assert overview["movement"]["rate_per_hour"] == 60
    assert overview["movement"]["active_hours_to_clear"] == 1


def test_overview_selects_the_weekend_operating_lane(monkeypatch):
    now = datetime(2026, 8, 22, 10, 0, tzinfo=ZONE)
    repository = Mock()
    repository.get_policy.return_value = {"enabled": False, "last_run_status": "NEVER"}
    repository.recent_actions.return_value = []
    repository.policy_audit.return_value = []
    repository.recent_samples.return_value = []
    gateway = Mock()
    gateway.configured = True
    gateway.counts.return_value = {
        "pending_count": 25,
        "created_count": 200,
        "overdue_count": 0,
        "due_today_count": 25,
        "future_count": 0,
    }
    service = HoveringMonitorService(repository=repository, gateway=gateway)
    monkeypatch.setattr(service, "local_now", lambda: now)

    overview = service.overview()

    assert overview["window"]["mode"] == "WEEKEND"
    assert overview["window"]["end"] == "09:00"
    assert overview["movement"]["window_open"] is False
    assert overview["movement"]["posture"] == "PAUSED"


def test_manual_date_repair_is_written_to_custody_history(monkeypatch):
    repository = Mock()
    repository.record_date_action.return_value = {
        "action_id": "action-1",
        "updated_count": 2,
        "status": "COMPLETED",
    }
    gateway = Mock()
    gateway.resolve_stale_dates.return_value = 2
    service = HoveringMonitorService(repository=repository, gateway=gateway)
    monkeypatch.setattr(
        service,
        "local_now",
        lambda: datetime(2026, 8, 21, 8, 0, tzinfo=ZONE),
    )

    result = service.resolve_dates(actor="operator.one", trigger="MANUAL", record_ids=["row-1", "row-2"])

    assert result["updated_count"] == 2
    gateway.resolve_stale_dates.assert_called_once_with(
        business_day=datetime(2026, 8, 21).date(),
        record_ids=["row-1", "row-2"],
    )
    repository.record_date_action.assert_called_once_with(
        trigger="MANUAL",
        actor="operator.one",
        requested_ids=["row-1", "row-2"],
        updated_count=2,
        status="COMPLETED",
    )


def test_encryptor_accepts_the_approved_raw_text_contract():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/internal/encryption/encrypt"
        assert request.headers["content-type"] == "application/json"
        assert request.content == b'{"password":"Temporary@1"}'
        return httpx.Response(200, text="DysaIsfeVgMEUfHAX61oHg==")

    encryptor = RobotPasswordEncryptor(
        url="http://encryptor.internal/internal/encryption/encrypt",
        transport=httpx.MockTransport(handler),
    )

    assert encryptor.encrypt("Temporary@1") == "DysaIsfeVgMEUfHAX61oHg=="


def test_robot_password_rotation_never_writes_password_or_hash_to_custody():
    repository = Mock()
    repository.recent_setting_actions.return_value = []
    repository.record_setting_action.return_value = {"action_id": "setting-action-1"}
    gateway = Mock()
    gateway.update_robot_credential.return_value = {
        "id": "8",
        "key": "ROBHOV06",
        "credential_configured": True,
    }
    encryptor = Mock()
    encryptor.encrypt.return_value = "opaque-encrypted-value"
    service = HoveringMonitorService(repository=repository, gateway=gateway, encryptor=encryptor)

    result = service.rotate_robot_password(
        key="robhov06",
        password="Temporary@1",
        actor="operator.one",
    )

    assert result["key"] == "ROBHOV06"
    encryptor.encrypt.assert_called_once_with("Temporary@1")
    gateway.update_robot_credential.assert_called_once_with(
        key="ROBHOV06",
        encrypted_value="opaque-encrypted-value",
    )
    repository.record_setting_action.assert_called_once_with(
        setting_key="ROBHOV06",
        setting_kind="ROBOT_PASSWORD",
        actor="operator.one",
        status="COMPLETED",
        error=None,
    )
    assert "Temporary@1" not in repr(repository.record_setting_action.call_args)
    assert "opaque-encrypted-value" not in repr(repository.record_setting_action.call_args)


def test_general_configuration_cannot_bypass_robot_password_protection():
    service = HoveringMonitorService(repository=Mock(), gateway=Mock(), encryptor=Mock())

    with pytest.raises(ValueError, match="protected password rotation"):
        service.update_general_configuration(
            key="ROBHOV03",
            value="not-an-encrypted-password",
            actor="admin.one",
        )


def test_unknown_hovering_status_is_rejected_before_querying_source():
    gateway = HoveringQueueGateway(dsn=None)

    with pytest.raises(ValueError, match="Unknown hovering queue status"):
        gateway.records(
            page=1,
            page_size=25,
            status_filter="COMPLETED",
            lookup=None,
            created_from=None,
            created_to=None,
        )
