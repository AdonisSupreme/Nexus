"""Email utilities for Sentinel Nexus operator control gates."""

from __future__ import annotations

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
    safe_operator = escape(operator_name)
    safe_service = escape(service_name)
    safe_service_id = escape(service_id)
    safe_operation = escape(operation.upper())
    safe_code = escape(code)
    safe_reason = escape(reason or "No operator reason supplied.")
    return f"""\
<!DOCTYPE html>
<html>
  <body style="margin:0;padding:28px;background:#020617;font-family:'Segoe UI','Helvetica Neue',Arial,sans-serif;color:#e2e8f0;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:720px;margin:0 auto;border-collapse:separate;border-spacing:0;">
      <tr>
        <td style="border-radius:28px;overflow:hidden;border:1px solid rgba(34,211,238,0.28);box-shadow:0 28px 80px rgba(2,6,23,0.58);background:linear-gradient(145deg,#04111f 0%,#091427 52%,#07101d 100%);">
          <div style="padding:30px 34px;background:radial-gradient(circle at 18% 0%,rgba(34,211,238,0.28),transparent 34%),radial-gradient(circle at 88% 12%,rgba(236,72,153,0.18),transparent 28%);">
            <div style="display:inline-block;padding:7px 12px;border-radius:999px;background:rgba(34,211,238,0.14);color:#67e8f9;font-size:11px;font-weight:800;letter-spacing:0.18em;text-transform:uppercase;">Sentinel Nexus Control Gate</div>
            <h1 style="margin:18px 0 8px;font-size:31px;line-height:1.12;color:#f8fafc;">Verify {safe_operation} for {safe_service}</h1>
            <p style="margin:0;color:#cbd5e1;font-size:15px;line-height:1.7;">Nexus is holding this control action until you confirm the one-time phrase below. This protects production-grade services from accidental or impersonated execution.</p>
          </div>
          <div style="padding:28px 34px 34px;">
            <div style="margin:0 0 22px;padding:22px;border-radius:22px;background:linear-gradient(135deg,rgba(34,211,238,0.13),rgba(59,130,246,0.08));border:1px solid rgba(34,211,238,0.22);text-align:center;">
              <div style="color:#94a3b8;font-size:12px;font-weight:800;letter-spacing:0.16em;text-transform:uppercase;">One-time verification code</div>
              <div style="margin-top:10px;color:#ffffff;font-size:42px;font-weight:900;letter-spacing:0.24em;">{safe_code}</div>
              <div style="margin-top:8px;color:#fbbf24;font-size:13px;">Expires in {expires_minutes} minutes</div>
            </div>
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;background:rgba(15,23,42,0.66);border-radius:18px;overflow:hidden;border:1px solid rgba(148,163,184,0.16);">
              <tr><td style="padding:12px 16px;color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:0.1em;">Operator</td><td style="padding:12px 16px;text-align:right;color:#e2e8f0;">{safe_operator}</td></tr>
              <tr><td style="padding:12px 16px;color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:0.1em;border-top:1px solid rgba(148,163,184,0.13);">Service ID</td><td style="padding:12px 16px;text-align:right;color:#e2e8f0;border-top:1px solid rgba(148,163,184,0.13);">{safe_service_id}</td></tr>
              <tr><td style="padding:12px 16px;color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:0.1em;border-top:1px solid rgba(148,163,184,0.13);">Reason</td><td style="padding:12px 16px;text-align:right;color:#e2e8f0;border-top:1px solid rgba(148,163,184,0.13);">{safe_reason}</td></tr>
            </table>
            <p style="margin:22px 0 0;color:#64748b;font-size:12px;line-height:1.6;">If this was not you, ignore the code and alert the SentinelOps administrator. Nexus will reject expired or reused codes automatically.</p>
          </div>
        </td>
      </tr>
    </table>
  </body>
</html>
"""


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
    accent = "#34d399" if recovered else "#fb7185"
    event_label = "RECOVERY CONFIRMED" if recovered else "INCIDENT DETECTED"
    safe_services = escape(", ".join(affected_services) or "Pending scope")
    safe_ended = escape(ended_at or "Still active")
    return f"""\
<!DOCTYPE html>
<html>
  <body style="margin:0;padding:28px;background:#020617;font-family:'Segoe UI','Helvetica Neue',Arial,sans-serif;color:#e2e8f0;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:760px;margin:0 auto;border-collapse:separate;border-spacing:0;">
      <tr>
        <td style="border-radius:26px;overflow:hidden;border:1px solid rgba(56,189,248,0.25);background:linear-gradient(145deg,#061323,#0b172b 58%,#07111f);box-shadow:0 30px 90px rgba(2,6,23,0.6);">
          <div style="padding:30px 34px;background:radial-gradient(circle at 12% 0%,rgba(56,189,248,0.24),transparent 34%),radial-gradient(circle at 92% 8%,{accent}24,transparent 32%);">
            <div style="display:inline-block;padding:7px 12px;border-radius:999px;border:1px solid {accent}66;background:{accent}1f;color:{accent};font-size:11px;font-weight:800;letter-spacing:0.17em;">{event_label}</div>
            <h1 style="margin:18px 0 10px;color:#f8fafc;font-size:30px;line-height:1.16;">{escape(incident_title)}</h1>
            <p style="margin:0;color:#cbd5e1;font-size:15px;line-height:1.7;">{escape(summary)}</p>
          </div>
          <div style="padding:0 34px 34px;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;border:1px solid rgba(148,163,184,0.16);background:rgba(15,23,42,0.72);">
              <tr><td style="padding:13px 16px;color:#94a3b8;font-size:12px;letter-spacing:0.08em;">RISK</td><td style="padding:13px 16px;text-align:right;color:{accent};font-weight:800;">{escape(risk_level)}</td></tr>
              <tr><td style="padding:13px 16px;border-top:1px solid rgba(148,163,184,0.13);color:#94a3b8;font-size:12px;letter-spacing:0.08em;">FAILURE DOMAIN</td><td style="padding:13px 16px;border-top:1px solid rgba(148,163,184,0.13);text-align:right;color:#e2e8f0;">{escape(failure_domain or 'unknown')}</td></tr>
              <tr><td style="padding:13px 16px;border-top:1px solid rgba(148,163,184,0.13);color:#94a3b8;font-size:12px;letter-spacing:0.08em;">ROOT CANDIDATE</td><td style="padding:13px 16px;border-top:1px solid rgba(148,163,184,0.13);text-align:right;color:#e2e8f0;">{escape(root_service or 'Pending correlation')}</td></tr>
              <tr><td style="padding:13px 16px;border-top:1px solid rgba(148,163,184,0.13);color:#94a3b8;font-size:12px;letter-spacing:0.08em;">AFFECTED SERVICES</td><td style="padding:13px 16px;border-top:1px solid rgba(148,163,184,0.13);text-align:right;color:#e2e8f0;">{safe_services}</td></tr>
              <tr><td style="padding:13px 16px;border-top:1px solid rgba(148,163,184,0.13);color:#94a3b8;font-size:12px;letter-spacing:0.08em;">STARTED</td><td style="padding:13px 16px;border-top:1px solid rgba(148,163,184,0.13);text-align:right;color:#e2e8f0;">{escape(started_at)}</td></tr>
              <tr><td style="padding:13px 16px;border-top:1px solid rgba(148,163,184,0.13);color:#94a3b8;font-size:12px;letter-spacing:0.08em;">RECOVERY</td><td style="padding:13px 16px;border-top:1px solid rgba(148,163,184,0.13);text-align:right;color:#e2e8f0;">{safe_ended}</td></tr>
            </table>
            <p style="margin:22px 0 5px;color:#cbd5e1;font-size:13px;line-height:1.6;">Open Sentinel Nexus Incident Intelligence for the live evidence fabric, dependency scope, and guarded response path.</p>
            <p style="margin:0;color:#64748b;font-size:11px;">Incident ID: {escape(incident_id)}</p>
          </div>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
