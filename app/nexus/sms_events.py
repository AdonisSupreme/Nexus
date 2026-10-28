"""One shared LISTEN connection per API process, active only while viewed.

Events are invalidations, never customer data. Without the source trigger the
explicit fallback is one-second invalidation, not claimed event-driven delivery.
"""
import logging
from threading import Lock, Thread
from time import monotonic, sleep

from app.config.settings import settings
from app.nexus.sms_monitor import SmsMonitor, invalidate_sms_cache

log = logging.getLogger(__name__)


class SmsEvents:
    def __init__(self):
        self.lock = Lock()
        self.users = 0
        self.thread = None
        self.revision = 0
        self.mode = 'connecting'
        self.last_seen = monotonic()

    def subscribe(self):
        with self.lock:
            self.users += 1
            if self.thread is None:
                self.thread = Thread(target=self.run, name='sms-source-listener', daemon=True)
                self.thread.start()

    def unsubscribe(self):
        with self.lock:
            self.users = max(0, self.users - 1)

    def active(self):
        with self.lock:
            return self.users > 0

    def publish(self, mode):
        invalidate_sms_cache()
        with self.lock:
            self.mode = mode
            self.revision += 1
            self.last_seen = monotonic()

    def snapshot(self):
        with self.lock:
            mode = self.mode
            if mode in ('realtime', 'polling') and monotonic() - self.last_seen > 5:
                mode = 'unavailable'
            return {'revision': self.revision, 'mode': mode}

    @staticmethod
    def trigger_ready(conn):
        row = conn.execute("""SELECT count(*) = 2 FROM pg_trigger t
            JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relname='queue' AND NOT t.tgisinternal
            AND t.tgenabled IN ('O','A')
            AND t.tgname IN ('sentinelops_sms_queue_change','sentinelops_sms_queue_truncate')""").fetchone()
        return bool(row and row[0])

    def listen(self):
        import psycopg
        with psycopg.connect(host=settings.SMSAL_HOST, port=settings.SMSAL_PORT,
                user=settings.SMSAL_USERNAME, password=settings.SMSAL_PASSWORD.get_secret_value(),
                dbname=settings.SMSAL_DATABASE, sslmode=settings.SMSAL_SSLMODE,
                connect_timeout=5, autocommit=True,
                keepalives=1, keepalives_idle=10, keepalives_interval=5,
                keepalives_count=2, tcp_user_timeout=15000,
                options='-c default_transaction_read_only=on -c statement_timeout=3000') as conn:
            conn.execute('LISTEN sentinelops_sms_queue')
            ready = self.trigger_ready(conn)
            mode = 'realtime' if ready else 'polling'
            self.publish(mode)  # Resnapshot on connection/reconnection: no event gap.
            probe = clock = monotonic()
            while self.active():
                changed = False
                # Consumed to completion every second; no idle source transaction.
                for _ in conn.notifies(timeout=1, stop_after=1):
                    changed = True
                now = monotonic()
                with self.lock:
                    self.last_seen = now
                if now - probe >= 10:
                    ready = self.trigger_ready(conn)
                    mode = 'realtime' if ready else 'polling'
                    probe = now
                if changed or not ready or now - clock >= 30:
                    self.publish(mode)
                    clock = now
                # Coalesce bursts without a queue proportional to event volume.
                if changed:
                    sleep(0.1)

    def run(self):
        while True:
            with self.lock:
                if not self.users:
                    self.thread = None
                    return
            try:
                if not SmsMonitor().configured:
                    self.publish('unconfigured')
                    sleep(1)
                else:
                    self.listen()
            except Exception as exc:
                log.warning('SMS listener unavailable (%s)', type(exc).__name__)
                self.publish('unavailable')
                sleep(1)


sms_events = SmsEvents()
