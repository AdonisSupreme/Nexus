# Nexus Incident Notifications

Nexus incident notifications are a Nexus Core capability. The Light Agent continues to collect evidence and execute guarded controls; it does not send operator notifications and requires no notification-specific configuration.

## Delivery Contract

- `OPENED` is emitted once when an incident lifecycle first enters `OPEN` or `MONITORING`.
- `RECOVERED` is emitted once when that lifecycle leaves active impact with an `end_time`.
- Repeated Light Agent, Loki, and Network Sentinel signals confirm the incident; they do not create duplicate notifications.
- Current-shift recipients come from active `checklist_instances` and `checklist_participants`, using the roster active at event time.
- Additional addresses receive email only. Current-shift users can receive both a persistent in-app alert and email.
- In-app alerts deep-link to `/nexus?incident=<incident-id>`.

## Reliability And Scale

Incident correlation writes a small idempotent outbox row in the same PostgreSQL transaction that persists the incident. SMTP and notification fanout run in a daemon dispatcher, never in the telemetry request thread.

Multiple Gunicorn workers safely compete for deliveries with `FOR UPDATE SKIP LOCKED`. Delivery keys prevent duplicate lifecycle queue entries. In-app IDs are deterministic, and email/in-app completion is tracked independently so a retry does not repeat a channel that already succeeded. Failed deliveries use bounded exponential retry and cannot fail or stall Nexus ingestion, service control, diagnostics, or the Light Agent.

In-app delivery is idempotent. Email is deliberately at-least-once: every retry uses the same deterministic `Message-ID`, but an SMTP timeout after the relay accepted a message can still produce a duplicate if that relay does not deduplicate message IDs. This is safer than silently losing a critical incident alert.

SentinelOps listens for PostgreSQL `NOTIFY` messages and pushes new Nexus alerts to each worker's connected WebSockets. Existing notification polling remains the recovery path if the real-time bridge is unavailable.

## Production Deployment

Apply the same migration file from either repository to the shared SentinelOps database. Apply it once; the SQL is idempotent.

```bash
cd /srv/Sentinel/Nexus
set -a
. ./.env
set +a
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f app/db/migrations/2026_19_add_nexus_incident_notifications.sql
```

Nexus email delivery uses the existing SMTP variables:

```dotenv
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USER=sysops-alerts@afcholdings.co.zw
SMTP_PASSWORD=<secret>
SMTP_FROM=sysops-alerts@afcholdings.co.zw
SMTP_USE_TLS=false
SMTP_STARTTLS=true
```

Restart Nexus Core and the SentinelOps API after deploying both codebases. With the known Nexus unit:

```bash
sudo systemctl restart sentnex.service
sudo systemctl status sentnex.service --no-pager -l
```

Restart the production SentinelOps API using its actual systemd unit name so the PostgreSQL-to-WebSocket bridge becomes active. Do not restart a Light Agent for this feature.

## Administrative Configuration

Open **Nexus > Incidents > Incident Notification Mesh > Configure** as an administrator.

- **Incident notifications** is the global switch. Pausing it does not pause correlation or incident persistence.
- **Current shift** selects the active SentinelOps shift roster.
- **In-app alert** creates the persistent, deep-linked alert and live popup.
- **Email alert** sends the incident intelligence email through the Nexus SMTP relay.
- **Recovery signal** sends a lifecycle message when operational impact ends.
- **Additional email recipients** accepts up to 50 newline-, comma-, or semicolon-separated addresses.

Only administrators receive the configured address list from the Nexus API. Other authorized Nexus users see the aggregate recipient count and delivery health without the addresses.

## Verification

```sql
SELECT * FROM nexus_incident_notification_setting;

SELECT delivery_key, event_type, status, attempts, recipient_count,
       delivered_count, in_app_delivered, email_delivered,
       created_at, delivered_at, last_error
FROM nexus_incident_notification_delivery
ORDER BY created_at DESC
LIMIT 20;
```

Confirm Nexus logs show dispatcher startup and successful delivery. Confirm an active-shift user receives an in-app notification that opens the exact incident, and that shift/additional recipients receive one email. On recovery, verify one `RECOVERED` delivery when recovery notifications are enabled.

## Failure Interpretation

- `RETRY`: a channel failed temporarily and will retry without repeating a completed channel.
- `PARTIAL`: retries were exhausted after at least one channel succeeded.
- `FAILED`: retries were exhausted before any channel succeeded.
- `NO_RECIPIENTS`: no current-shift users or additional email addresses were available.
- `SUPPRESSED`: notifications or recovery messages were disabled when the lifecycle event occurred.
