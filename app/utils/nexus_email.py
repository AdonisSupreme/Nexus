"""Email utilities for Sentinel Nexus operator control gates."""

from __future__ import annotations

from email.message import EmailMessage
from html import escape
import smtplib
import ssl
import threading

from app.config.settings import settings
from app.utils.logging import get_logger


logger = get_logger(__name__)


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
        context = ssl.create_default_context()
        password = settings.SMTP_PASSWORD.get_secret_value() if settings.SMTP_PASSWORD else None
        if settings.SMTP_USE_TLS:
            with smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, context=context, timeout=15) as server:
                _login_if_configured(server, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as server:
                if settings.SMTP_STARTTLS:
                    server.starttls(context=context)
                _login_if_configured(server, password)
                server.send_message(msg)
        logger.info("Sent Nexus control OTP email to %s for %s %s", recipient, operation, service_id)
    except Exception:
        logger.exception("Failed to send Nexus control OTP email to %s", recipient)


def _login_if_configured(server: smtplib.SMTP, password: str | None) -> None:
    if settings.SMTP_USER and password:
        server.login(settings.SMTP_USER, password)


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
