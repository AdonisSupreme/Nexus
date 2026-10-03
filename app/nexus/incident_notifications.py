"""Failure-isolated delivery worker for Sentinel Nexus incident notifications."""

from __future__ import annotations

from datetime import datetime, timezone
import os
import socket
import threading
from typing import Any, Callable
from uuid import uuid4

from app.nexus.repository import NexusRepository
from app.utils.logging import get_logger
from app.utils.nexus_email import send_nexus_incident_notification


logger = get_logger(__name__)


class NexusIncidentNotificationDispatcher:
    """Claim durable outbox rows and deliver them outside request processing."""

    IDLE_POLL_SECONDS = 5
    MAX_ATTEMPTS = 5

    def __init__(
        self,
        repository: NexusRepository,
        *,
        email_sender: Callable[..., None] = send_nexus_incident_notification,
    ) -> None:
        self.repository = repository
        self.email_sender = email_sender
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._thread: threading.Thread | None = None
        self.worker_id = f"{socket.gethostname()}:{os.getpid()}:{uuid4().hex[:8]}"

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="nexus-incident-notifications",
            daemon=True,
        )
        self._thread.start()
        self.wake()
        logger.info("Nexus incident notification dispatcher started as %s", self.worker_id)

    def stop(self) -> None:
        self._stop_event.set()
        self._wake_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        if self._thread and self._thread.is_alive():
            logger.warning(
                "Nexus incident notification dispatcher is still completing an in-flight delivery for %s",
                self.worker_id,
            )
        else:
            logger.info("Nexus incident notification dispatcher stopped for %s", self.worker_id)

    def wake(self) -> None:
        self._wake_event.set()

    def _run(self) -> None:
        while not self._stop_event.is_set():
            delivery: dict[str, Any] | None = None
            try:
                delivery = self.repository.claim_next_incident_notification(self.worker_id)
                if delivery:
                    self._process_delivery(delivery)
                    continue
            except Exception as exc:
                logger.exception("Nexus incident notification dispatch cycle failed")
                if delivery:
                    try:
                        self._record_delivery_failure(
                            delivery,
                            exc,
                            int(delivery.get("recipient_count") or 0),
                            int(delivery.get("delivered_count") or 0),
                            bool(delivery.get("in_app_delivered")),
                            bool(delivery.get("email_delivered")),
                        )
                    except Exception:
                        logger.exception(
                            "Could not record Nexus incident notification failure for %s; "
                            "the durable claim will be reclaimed after its lease expires",
                            delivery.get("delivery_key"),
                        )

            self._wake_event.wait(self.IDLE_POLL_SECONDS)
            self._wake_event.clear()

    def _process_delivery(self, delivery: dict[str, Any]) -> None:
        notification_settings = self.repository.get_incident_notification_settings()
        in_app_delivered = bool(delivery.get("in_app_delivered"))
        email_delivered = bool(delivery.get("email_delivered"))
        delivered_count = int(delivery.get("delivered_count") or 0)

        if not notification_settings.schema_ready or not notification_settings.enabled:
            self.repository.complete_incident_notification_delivery(
                delivery["delivery_key"],
                status_value="SUPPRESSED",
                recipient_count=0,
                delivered_count=delivered_count,
                in_app_delivered=in_app_delivered,
                email_delivered=email_delivered,
                last_error="Nexus incident notifications are currently disabled.",
            )
            return
        if delivery["event_type"] == "RECOVERED" and not notification_settings.notify_on_recovery:
            self.repository.complete_incident_notification_delivery(
                delivery["delivery_key"],
                status_value="SUPPRESSED",
                recipient_count=0,
                delivered_count=delivered_count,
                in_app_delivered=in_app_delivered,
                email_delivered=email_delivered,
                last_error="Nexus recovery notifications are currently disabled.",
            )
            return

        payload = delivery.get("payload") or {}
        incident = payload.get("incident") or {}
        reference_time = self._event_reference_time(delivery, incident)
        contacts = (
            self.repository.list_current_shift_participant_contacts(reference_time)
            if notification_settings.notify_current_shift
            else []
        )
        email_recipients = list(
            dict.fromkeys(
                [
                    *(str(contact.get("email") or "").strip().lower() for contact in contacts),
                    *notification_settings.additional_email_recipients,
                ]
            )
        )
        email_recipients = [recipient for recipient in email_recipients if recipient]
        in_app_target_count = len(contacts) if notification_settings.in_app_enabled else 0
        email_target_count = len(email_recipients) if notification_settings.email_enabled else 0
        recipient_count = in_app_target_count + email_target_count

        if recipient_count == 0:
            self.repository.complete_incident_notification_delivery(
                delivery["delivery_key"],
                status_value="NO_RECIPIENTS",
                recipient_count=0,
                delivered_count=delivered_count,
                in_app_delivered=not notification_settings.in_app_enabled or not contacts,
                email_delivered=not notification_settings.email_enabled or not email_recipients,
                last_error="No active-shift or additional email recipients were available.",
            )
            logger.warning(
                "Nexus incident notification %s had no configured recipients",
                delivery["delivery_key"],
            )
            return

        errors: list[str] = []
        if not notification_settings.in_app_enabled or not contacts:
            in_app_delivered = True
        elif not in_app_delivered:
            try:
                delivered_count += self.repository.create_incident_in_app_notifications(delivery, contacts)
                in_app_delivered = True
            except Exception as exc:
                errors.append(f"in-app delivery failed: {exc}")
                logger.exception("Nexus in-app incident notification failed for %s", delivery["delivery_key"])

        if not notification_settings.email_enabled or not email_recipients:
            email_delivered = True
        elif not email_delivered:
            try:
                self.email_sender(
                    recipients=email_recipients,
                    delivery_key=delivery["delivery_key"],
                    event_type=delivery["event_type"],
                    incident_id=str(delivery["incident_id"]),
                    incident_title=str(incident.get("title") or "Sentinel Nexus incident"),
                    summary=str(incident.get("summary") or "Nexus detected a correlated service incident."),
                    risk_level=str(incident.get("risk_level") or "MEDIUM"),
                    failure_domain=str(incident.get("failure_domain") or "unknown"),
                    affected_services=list(incident.get("affected_services") or []),
                    root_service=(
                        incident.get("suspected_root_service_name")
                        or incident.get("suspected_root_service")
                    ),
                    started_at=str(incident.get("start_time") or delivery["incident_started_at"]),
                    ended_at=str(incident.get("end_time")) if incident.get("end_time") else None,
                )
                delivered_count += email_target_count
                email_delivered = True
            except Exception as exc:
                errors.append(f"email delivery failed: {exc}")

        if errors:
            self._record_delivery_failure(
                delivery,
                RuntimeError("; ".join(errors)),
                recipient_count,
                delivered_count,
                in_app_delivered,
                email_delivered,
            )
            return

        self.repository.complete_incident_notification_delivery(
            delivery["delivery_key"],
            status_value="SENT",
            recipient_count=recipient_count,
            delivered_count=delivered_count,
            in_app_delivered=in_app_delivered,
            email_delivered=email_delivered,
        )
        logger.info(
            "Delivered Nexus %s notification for incident %s to %d channel recipient(s)",
            str(delivery["event_type"]).lower(),
            delivery["incident_id"],
            recipient_count,
        )

    def _record_delivery_failure(
        self,
        delivery: dict[str, Any],
        exc: Exception,
        recipient_count: int,
        delivered_count: int,
        in_app_delivered: bool,
        email_delivered: bool,
    ) -> None:
        error_message = str(exc)[:2000]
        attempts = int(delivery.get("attempts") or 1)
        if attempts >= self.MAX_ATTEMPTS:
            self.repository.complete_incident_notification_delivery(
                delivery["delivery_key"],
                status_value="PARTIAL" if delivered_count else "FAILED",
                recipient_count=recipient_count,
                delivered_count=delivered_count,
                in_app_delivered=in_app_delivered,
                email_delivered=email_delivered,
                last_error=error_message,
            )
            logger.error(
                "Nexus incident notification %s exhausted %d attempt(s): %s",
                delivery["delivery_key"],
                attempts,
                error_message,
            )
            return

        delay_seconds = min(480, 30 * (2 ** max(0, attempts - 1)))
        self.repository.retry_incident_notification_delivery(
            delivery["delivery_key"],
            delay_seconds=delay_seconds,
            recipient_count=recipient_count,
            delivered_count=delivered_count,
            in_app_delivered=in_app_delivered,
            email_delivered=email_delivered,
            last_error=error_message,
        )
        logger.warning(
            "Nexus incident notification %s will retry in %d seconds: %s",
            delivery["delivery_key"],
            delay_seconds,
            error_message,
        )

    @staticmethod
    def _event_reference_time(delivery: dict[str, Any], incident: dict[str, Any]) -> datetime:
        raw_value = incident.get("end_time") if delivery.get("event_type") == "RECOVERED" else None
        raw_value = raw_value or incident.get("start_time") or delivery.get("incident_started_at")
        if isinstance(raw_value, datetime):
            return raw_value if raw_value.tzinfo else raw_value.replace(tzinfo=timezone.utc)
        try:
            parsed = datetime.fromisoformat(str(raw_value).replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return datetime.now(timezone.utc)
