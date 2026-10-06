"""Email utilities for Sentinel Nexus operator control gates."""

from __future__ import annotations
from app.utils.email_design import render_email

import asyncio
from email.message import EmailMessage
import hashlib
from html import escape
import smtplib
import ssl
import threading
from typing import Iterable

from app.config.settings import settings
from app.utils.logging import get_logger

try:
    import aiosmtplib
except ImportError:  # pragma: no cover - production should install requirements.txt
    aiosmtplib = None


logger = get_logger(__name__)


def send_nexus_incident_notification(
    *,
    recipients: Iterable[str],
    delivery_key: str,
    event_type: str,
    incident_id: str,
    incident_title: str,
    summary: str,
    risk_level: str,
    failure_domain: str,
    affected_services: list[str],
    root_service: str | None,
    started_at: str,
    ended_at: str | None,
) -> None:
    """Deliver one durable Nexus incident email from the outbox worker."""
    recipient_list = list(
        dict.fromkeys(
            recipient.strip().lower()
            for recipient in recipients
            if recipient and recipient.strip()
        )
    )
    if not recipient_list:
        return
    if not settings.SMTP_HOST or not settings.SMTP_FROM:
        raise RuntimeError("SMTP_HOST and SMTP_FROM must be configured for Nexus incident email notifications.")

    normalized_event = event_type.strip().upper()
    normalized_risk = risk_level.strip().upper() or "MEDIUM"
    subject_prefix = "RECOVERED" if normalized_event == "RECOVERED" else normalized_risk
    msg = EmailMessage()
    msg["From"] = settings.SMTP_FROM
    msg["To"] = settings.SMTP_FROM
    msg["Bcc"] = ", ".join(recipient_list)
    msg["Subject"] = f"[Sentinel Nexus] {subject_prefix}: {incident_title}"
    message_hash = hashlib.sha256(delivery_key.encode("utf-8")).hexdigest()[:32]
    msg["Message-ID"] = f"<{message_hash}.nexus.incident@sentinelops.local>"
    state_line = (
        "Operational impact has ended and Nexus is awaiting the operator verdict."
        if normalized_event == "RECOVERED"
        else "Nexus has correlated a new operational incident."
    )
    msg.set_content(
        "\n".join(
            [
                "Sentinel Nexus Incident Intelligence",
                "",
                state_line,
                f"Incident: {incident_title}",
                f"Risk: {normalized_risk}",
                f"Failure domain: {failure_domain or 'unknown'}",
                f"Probable root cause: {root_service or 'Pending correlation'}",
                f"Affected services: {', '.join(affected_services) or 'Pending scope'}",
                f"Started: {started_at}",
                *((f"Recovered: {ended_at}",) if ended_at else ()),
                "",
                summary,
                "",
                f"Incident ID: {incident_id}",
                "Open Sentinel Nexus Incident Intelligence for live evidence, topology, and the guarded response path.",
            ]
        )
    )
    msg.add_alternative(
        _incident_notification_html(
            event_type=normalized_event,
            incident_id=incident_id,
            incident_title=incident_title,
            summary=summary,
            risk_level=normalized_risk,
            failure_domain=failure_domain,
            affected_services=affected_services,
            root_service=root_service,
            started_at=started_at,
            ended_at=ended_at,
        ),
        subtype="html",
    )

    try:
        password = settings.SMTP_PASSWORD.get_secret_value() if settings.SMTP_PASSWORD else ""
        if aiosmtplib is not None:
            asyncio.run(_send_with_beta_transport(msg, password))
        else:
            _send_with_smtplib(msg, password)
        logger.info(
            "Sent Nexus %s notification for incident %s to %d recipient(s)",
            normalized_event.lower(),
            incident_id,
            len(recipient_list),
        )
    except Exception:
        logger.exception(
            "Failed to send Nexus %s notification for incident %s",
            normalized_event.lower(),
            incident_id,
        )
        raise


def send_nexus_control_otp(
    *,
    recipient: str,
    operator_name: str,
    service_name: str,
    service_id: str,
    operation: str,
    code: str,
    expires_minutes: int,
    reason: str | None = None,
) -> None:
    """Send the one-time control code without blocking the API request thread."""
    thread = threading.Thread(
        target=_send_nexus_control_otp_sync,
        kwargs={
            "recipient": recipient,
            "operator_name": operator_name,
            "service_name": service_name,
            "service_id": service_id,
            "operation": operation,
            "code": code,
            "expires_minutes": expires_minutes,
            "reason": reason,
        },
        name="nexus-control-otp-email",
        daemon=True,
    )
    thread.start()


def _send_nexus_control_otp_sync(
    *,
    recipient: str,
    operator_name: str,
    service_name: str,
    service_id: str,
    operation: str,
    code: str,
    expires_minutes: int,
    reason: str | None,
) -> None:
    if not settings.SMTP_HOST or not settings.SMTP_FROM:
        logger.warning("SMTP is not configured; Nexus control OTP email was not sent.")
        return

    subject = f"Sentinel Nexus {operation.upper()} verification for {service_name}"
    msg = EmailMessage()
    msg["From"] = settings.SMTP_FROM
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(
        "\n".join(
            [
                "Sentinel Nexus Control Verification",
                "",
                f"Operator: {operator_name}",
                f"Service: {service_name} ({service_id})",
                f"Requested action: {operation.upper()}",
                f"One-time code: {code}",
                f"Expires in: {expires_minutes} minutes",
                "",
                reason or "No operator reason was supplied.",
                "",
                "If you did not request this action, do not share this code and contact the SentinelOps administrator.",
            ]
        )
    )
    msg.add_alternative(
        _control_otp_html(
            operator_name=operator_name,
            service_name=service_name,
            service_id=service_id,
            operation=operation,
            code=code,
            expires_minutes=expires_minutes,
            reason=reason,
        ),
        subtype="html",
    )

    try:
        password = settings.SMTP_PASSWORD.get_secret_value() if settings.SMTP_PASSWORD else ""
        if aiosmtplib is not None:
            asyncio.run(_send_with_beta_transport(msg, password))
        else:
            logger.warning("aiosmtplib is not installed; Nexus is using the legacy SMTP fallback.")
            _send_with_smtplib(msg, password)
        logger.info("Sent Nexus control OTP email to %s for %s %s", recipient, operation, service_id)
    except Exception:
        logger.exception("Failed to send Nexus control OTP email to %s", recipient)


async def _send_with_beta_transport(msg: EmailMessage, password: str) -> None:
    """Mirror SentinelOps-beta's app.core.emailer SMTP transport."""
    send_kwargs = {
        "hostname": settings.SMTP_HOST,
        "port": settings.SMTP_PORT,
        "username": settings.SMTP_USER or "",
        "password": password,
        "start_tls": settings.SMTP_STARTTLS,
        "timeout": 15,
    }
    if settings.SMTP_USE_TLS:
        send_kwargs["use_tls"] = True
        send_kwargs["start_tls"] = False
    await aiosmtplib.send(msg, **send_kwargs)


def _send_with_smtplib(msg: EmailMessage, password: str) -> None:
    context = ssl.create_default_context()
    if settings.SMTP_USE_TLS:
        with smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, context=context, timeout=15) as server:
            _login_if_configured(server, settings.SMTP_USER or "", password)
            server.send_message(msg)
    else:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as server:
            if settings.SMTP_STARTTLS:
                server.starttls(context=context)
            _login_if_configured(server, settings.SMTP_USER or "", password)
            server.send_message(msg)


def _login_if_configured(server: smtplib.SMTP, username: str, password: str) -> None:
    if username and password:
        server.login(username, password, initial_response_ok=False)


def _control_otp_html(
    *,
    operator_name: str,
    service_name: str,
    service_id: str,
    operation: str,
    code: str,
    expires_minutes: int,
    reason: str | None,
) -> str:
    return render_email(badge="Nexus control verification", headline=f"Verify {operation.upper()} for {service_name}", intro="Return to your active control request and enter this one-time code to confirm the operation.", code=code, code_hint=f"Expires in {expires_minutes} minutes", metadata=[("Operator", operator_name), ("Service ID", service_id), ("Operation", operation.upper()), ("Reason", reason or "No operator reason supplied.")], lines=["If this was not you, ignore the code and alert the SentinelOps administrator. Expired or reused codes are rejected."])


def _incident_notification_html(
    *,
    event_type: str,
    incident_id: str,
    incident_title: str,
    summary: str,
    risk_level: str,
    failure_domain: str,
    affected_services: list[str],
    root_service: str | None,
    started_at: str,
    ended_at: str | None,
) -> str:
    recovered = event_type == "RECOVERED"
    return render_email(badge="Recovery confirmed" if recovered else "Incident detected", headline=incident_title, intro=summary, metadata=[("Risk", risk_level), ("Failure domain", failure_domain or "unknown"), ("Root candidate", root_service or "Pending correlation"), ("Affected services", ", ".join(affected_services) or "Pending scope"), ("Started", started_at), ("Recovery", ended_at or "Still active"), ("Incident ID", incident_id)], lines=["Open Sentinel Nexus Incident Intelligence for live evidence, topology and the guarded response path."])
