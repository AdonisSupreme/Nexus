"""Explicit, bounded recovery with durable intent before touching source records.

Source and custody databases cannot share a transaction. APPLYING/UNCERTAIN
actions must be reconciled, never automatically retried after a connection loss.
"""
from datetime import datetime, timezone
from uuid import uuid4

from psycopg.types.json import Jsonb

from app.config.settings import settings
from app.nexus.hovering_monitor import HoveringQueueGateway, HoveringMonitorRepository


MAX_RECOVERY = 500


class HoveringRecoveryGateway(HoveringQueueGateway):
    def where(self, filters):
        if filters.get('created_from') and filters.get('created_to'):
            if datetime.fromisoformat(filters['created_from']) >= datetime.fromisoformat(filters['created_to']):
                raise ValueError('Created before must be later than created from.')
        clauses = ["type = %s", "credit_account = %s", "status = 'FAILED'"]
        values = [settings.NEXUS_HOVERING_TYPE, settings.NEXUS_HOVERING_CREDIT_ACCOUNT]
        ids = filters.get('record_ids')
        if ids is not None:
            if not ids or len(ids) > MAX_RECOVERY:
                raise ValueError('Select between 1 and 500 records.')
            clauses.append('id = ANY(%s)')
            values.append(ids)
        for name, expression in [('created_from', 'created >= %s'), ('created_to', 'created < %s')]:
            if filters.get(name):
                clauses.append(expression)
                values.append(filters[name])
        if filters.get('description') is not None:
            clauses.append("BTRIM(COALESCE(description, '')) = %s")
            values.append(filters['description'].strip())
        if filters.get('lookup'):
            clauses.append('(debit_account ILIKE %s OR reference ILIKE %s OR external_reference ILIKE %s OR id = %s)')
            value = filters['lookup'].strip()
            values.extend([f'%{value}%'] * 3 + [value])
        return ' AND '.join(clauses), values

    def reasons(self):
        where, values = self.where({})
        with self.connection() as conn:
            rows = conn.execute(f"SELECT BTRIM(COALESCE(description, '')) AS description, COUNT(*) AS count FROM hovering WHERE {where} GROUP BY 1 ORDER BY count DESC, description", values).fetchall()
        return [dict(row) for row in rows]

    def snapshot(self, conn, filters, lock=False):
        where, values = self.where(filters)
        rows = conn.execute(f"SELECT id, status, description, amount, currency, debit_account, credit_account, type, reference, external_reference, installment_date, updated FROM hovering WHERE {where} ORDER BY id LIMIT %s" + (' FOR UPDATE' if lock else ''), (*values, MAX_RECOVERY + 1)).fetchall()
        if len(rows) > MAX_RECOVERY:
            raise ValueError('More than 500 failed records match. Narrow the filters before preparing recovery.')
        return [{key: str(value) if value is not None else None for key, value in row.items()} for row in rows]

    def preview(self, filters):
        with self.connection() as conn:
            return self.snapshot(conn, filters)

    def apply(self, evidence):
        ids = [row['id'] for row in evidence]
        with self.connection() as conn:
            # Lock and compare the complete reviewed evidence before any change.
            current = self.snapshot(conn, {'record_ids': ids}, lock=True)
            if current != evidence:
                raise ValueError('Records changed since review. Nothing was requeued; prepare a fresh review.')
            where, values = self.where({'record_ids': ids})
            result = conn.execute(f"UPDATE hovering SET status = 'PENDING' WHERE {where}", values)
            if result.rowcount != len(ids):
                raise ValueError('Recovery count changed. The source transaction was rolled back.')
            conn.commit()
        return len(ids)


class QueueRecovery:
    def __init__(self, queue='hovering', gateway=None, repository=None):
        self.queue = queue
        self.gateway = gateway or HoveringRecoveryGateway()
        self.repository = repository or HoveringMonitorRepository()

    def prepare(self, filters, actor):
        evidence = self.gateway.preview(filters)
        if not evidence:
            raise ValueError('No eligible failed records match this selection.')
        action_id = str(uuid4())
        with self.repository._connection() as conn:
            conn.execute("INSERT INTO nexus_queue_recovery(action_id, queue, actor, state, filters, evidence) VALUES (%s,%s,%s,'PREPARED',%s,%s)", (action_id, self.queue, actor, Jsonb(filters), Jsonb(evidence)))
            conn.commit()
        return {'action_id': action_id, 'count': len(evidence), 'requested_count': len(set(filters['record_ids'])) if filters.get('record_ids') else len(evidence), 'items': evidence, 'expires_in_seconds': 600}

    def execute(self, action_id, actor):
        with self.repository._connection() as conn:
            action = conn.execute("SELECT * FROM nexus_queue_recovery WHERE action_id=%s AND queue=%s AND actor=%s FOR UPDATE", (action_id, self.queue, actor)).fetchone()
            if not action or action['state'] != 'PREPARED' or action['expires_at'] <= datetime.now(timezone.utc):
                raise ValueError('Recovery review expired or has already been submitted. Refresh custody before retrying.')
            conn.execute("UPDATE nexus_queue_recovery SET state='APPLYING' WHERE action_id=%s", (action_id,))
            conn.commit()
        try:
            count = self.gateway.apply(action['evidence'])
        except Exception as exc:
            state = 'REJECTED' if isinstance(exc, ValueError) else 'UNCERTAIN'
            self.finish(action_id, state, 0)
            if state == 'UNCERTAIN':
                raise ValueError('Source outcome is uncertain. Ask an administrator to reconcile this custody action before retrying.') from exc
            raise
        try:
            self.finish(action_id, 'COMPLETED', count)
        except Exception as exc:
            raise ValueError('Source update completed but custody finalization failed. Do not retry; ask an administrator to reconcile the APPLYING action.') from exc
        return {'action_id': action_id, 'updated_count': count, 'state': 'COMPLETED'}

    def finish(self, action_id, state, count):
        with self.repository._connection() as conn:
            conn.execute("UPDATE nexus_queue_recovery SET state=%s, updated_count=%s, completed_at=now() WHERE action_id=%s", (state, count, action_id))
            conn.commit()

    def history(self, page):
        with self.repository._connection() as conn:
            rows = conn.execute("SELECT action_id, actor, state, updated_count, created_at, completed_at, evidence FROM nexus_queue_recovery WHERE queue=%s ORDER BY created_at DESC, action_id DESC LIMIT 26 OFFSET %s", (self.queue, (page - 1) * 25)).fetchall()
        return {'items': [dict(row) for row in rows[:25]], 'has_more': len(rows) > 25}
