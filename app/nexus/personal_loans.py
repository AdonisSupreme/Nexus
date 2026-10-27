"""Restricted MySQL view of the two approved 48-month personal-loan queues."""
from contextlib import contextmanager

from app.config.settings import settings
from app.nexus.queue_recovery import MAX_RECOVERY

TENURES = ('USD PERSONAL LOAN 48 MONTHS', 'ZWL PERSONAL LOAN 48 MONTHS')
STATES = {
    'PENDING': (31, '0'),
    'SUCCESS': (18, '1'),
    'FAILED': (18, '2'),
}
# Deliberate allow-list: no identity documents, salaries or family details.
FIELDS = 'id, account_number, approved_amount, currency, overdraft_tenure, status_id, is_processed, bot_message, bot_processed_LN, created_at, updated_at, processed_datetime, branch_origin, maturity, next_pay_date'
REPORT_FIELDS = FIELDS + ', full_name, amount_applied'
EXPORT_LIMIT = 10000


class PersonalLoanGateway:
    @property
    def configured(self):
        return bool(settings.OD_DB_HOST and settings.OD_DB_USERNAME and settings.OD_DB_PASSWORD)

    @contextmanager
    def connection(self):
        if not self.configured:
            raise ValueError('Personal loan source is not configured. Set the server-side OD_DB connection settings.')
        import pymysql
        conn = pymysql.connect(host=settings.OD_DB_HOST, port=settings.OD_DB_PORT,
            user=settings.OD_DB_USERNAME, password=settings.OD_DB_PASSWORD.get_secret_value(),
            database=settings.OD_DB_DATABASE, cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=5, read_timeout=15, write_timeout=15, autocommit=False, charset='utf8mb4')
        try:
            yield conn
        finally:
            conn.close()

    def where(self, filters, failed=False):
        clauses = ['overdraft_tenure IN (%s,%s)']
        values = list(TENURES)
        currency = filters.get('currency')
        if currency:
            if currency not in ('USD', 'ZWL'):
                raise ValueError('Choose USD, ZWL or both currencies.')
            clauses.append('overdraft_tenure=%s')
            values.append(f'{currency} PERSONAL LOAN 48 MONTHS')
        state = 'FAILED' if failed else filters.get('status')
        if state:
            if state not in STATES:
                raise ValueError('Unknown personal loan queue status.')
            clauses.extend(['status_id=%s', 'is_processed=%s'])
            values.extend(STATES[state])
        if filters.get('description') is not None:
            if state != 'FAILED':
                raise ValueError('Failure reasons require the Failed filter.')
            clauses.append("TRIM(COALESCE(bot_message,''))=%s")
            values.append(filters['description'].strip())
        if filters.get('record_ids') is not None:
            ids = filters['record_ids']
            if not ids or len(ids)>MAX_RECOVERY or any(not str(value).isdigit() for value in ids):
                raise ValueError('Supply between 1 and 500 numeric application IDs.')
            clauses.append('id IN (' + ','.join(['%s'] * len(ids)) + ')')
            values.extend(ids)
        if filters.get('lookup'):
            clauses.append('(account_number LIKE %s OR bot_processed_LN LIKE %s OR CAST(id AS CHAR)=%s OR full_name LIKE %s)')
            value=filters['lookup'].strip()
            values.extend([f'%{value}%', f'%{value}%', value, f'%{value}%'])
        if filters.get('branch'):
            clauses.append('branch_origin=%s')
            values.append(filters['branch'].strip())
        from datetime import date
        for key, column, operator in [('maturity_after','maturity','>'), ('maturity_to','maturity','<='), ('pay_from','next_pay_date','>='), ('pay_to','next_pay_date','<=')]:
            if filters.get(key):
                value = date.fromisoformat(str(filters[key]))
                clauses.append(f"STR_TO_DATE({column}, '%%Y-%%m-%%d') {operator} %s")
                values.append(value)
        for low, high in [('maturity_after','maturity_to'), ('pay_from','pay_to')]:
            if filters.get(low) and filters.get(high) and str(filters[low]) > str(filters[high]):
                raise ValueError('The end date must not precede the start date.')
        basis = filters.get('date_basis') or 'created'
        if basis not in ('created', 'processed'):
            raise ValueError('Choose created or processed dates.')
        date_column = 'processed_datetime' if basis == 'processed' else 'created_at'
        for key, expression in [('created_from',f'{date_column} >= %s'),('created_to',f'{date_column} < %s')]:
            if filters.get(key):
                from datetime import datetime
                from zoneinfo import ZoneInfo
                value = datetime.fromisoformat(filters[key].replace('Z','+00:00'))
                if value.tzinfo:
                    value = value.astimezone(ZoneInfo(settings.NEXUS_HOVERING_TIMEZONE)).replace(tzinfo=None)
                clauses.append(expression)
                values.append(value)
        if filters.get('created_from') and filters.get('created_to') and filters['created_from'] >= filters['created_to']:
            raise ValueError('Created before must be later than created from.')
        return ' AND '.join(clauses), values

    def records(self, filters, page=1, page_size=25):
        where, values=self.where(filters)
        with self.connection() as conn, conn.cursor() as cursor:
            cursor.execute(f'SELECT COUNT(*) AS total FROM overdraft_applications WHERE {where}', values)
            total=cursor.fetchone()['total']
            cursor.execute(f'SELECT {REPORT_FIELDS} FROM overdraft_applications WHERE {where} ORDER BY created_at DESC, id DESC LIMIT %s OFFSET %s', (*values,page_size,(page-1)*page_size))
            rows=cursor.fetchall()
        return {'items':rows,'total':total,'page':page,'pages':max(1,(total+page_size-1)//page_size),'page_size':page_size}

    def report(self, filters):
        """On-demand scoped aggregates; never mix monetary units or infer disbursement."""
        from datetime import datetime, timezone
        where, values = self.where(filters)
        column = 'processed_datetime' if filters.get('date_basis') == 'processed' else 'created_at'
        with self.connection() as conn, conn.cursor() as cursor:
            cursor.execute(f'''SELECT overdraft_tenure, status_id, is_processed, COUNT(*) AS total,
                COUNT(approved_amount) AS amounts_known, SUM(approved_amount) AS approved_total,
                MIN(approved_amount) AS approved_min, MAX(approved_amount) AS approved_max
                FROM overdraft_applications WHERE {where} GROUP BY overdraft_tenure,status_id,is_processed''', values)
            groups = cursor.fetchall()
            cursor.execute(f'''SELECT DATE({column}) AS day, overdraft_tenure, COUNT(*) AS total,
                SUM(status_id=18 AND is_processed='1') AS successful,
                SUM(status_id=18 AND is_processed='2') AS failed
                FROM overdraft_applications WHERE {where} AND {column} IS NOT NULL
                GROUP BY DATE({column}),overdraft_tenure ORDER BY day DESC,overdraft_tenure LIMIT 62''', values)
            activity = cursor.fetchall()
        return {'groups':groups,'activity':activity,'filters':filters,'generated_at':datetime.now(timezone.utc),
            'export_limit':EXPORT_LIMIT,'recovery_limit':MAX_RECOVERY,'timezone':settings.NEXUS_HOVERING_TIMEZONE}

    def export_csv(self, filters):
        """A bounded, per-request snapshot; never shared files or silent truncation."""
        import csv
        import io
        where, values = self.where(filters)
        with self.connection() as conn, conn.cursor() as cursor:
            cursor.execute(f'SELECT {REPORT_FIELDS} FROM overdraft_applications WHERE {where} ORDER BY id LIMIT %s', (*values,EXPORT_LIMIT+1))
            rows = cursor.fetchall()
        if len(rows) > EXPORT_LIMIT:
            raise ValueError('More than 10,000 records match. Narrow the reporting scope before downloading.')
        output = io.StringIO(newline='')
        writer = csv.writer(output)
        fields = REPORT_FIELDS.split(', ')
        writer.writerow(fields)
        for row in rows:
            writer.writerow([csv_cell(row.get(key)) for key in fields])
        return '\ufeff' + output.getvalue()

    def overview(self, currency=None):
        if not self.configured:
            return {'configured':False,'counts':{}}
        where, values=self.where({'currency': currency})
        with self.connection() as conn, conn.cursor() as cursor:
            cursor.execute(f'SELECT status_id,is_processed,COUNT(*) AS total FROM overdraft_applications WHERE {where} GROUP BY status_id,is_processed', values)
            counts={key:0 for key in [*STATES,'OTHER']}
            for row in cursor.fetchall():
                key=next((key for key,pair in STATES.items() if (row['status_id'],str(row['is_processed']))==pair),'OTHER')
                counts[key]+=row['total']
        from datetime import datetime, timezone
        return {'configured':True,'counts':counts,'refreshed_at':datetime.now(timezone.utc)}

    def reasons(self, currency=None):
        where, values=self.where({'currency': currency}, failed=True)
        with self.connection() as conn, conn.cursor() as cursor:
            cursor.execute(f"SELECT TRIM(COALESCE(bot_message,'')) AS description,COUNT(*) AS count FROM overdraft_applications WHERE {where} GROUP BY 1 ORDER BY count DESC, description", values)
            return cursor.fetchall()

    def snapshot(self, conn, filters, lock=False):
        where, values=self.where(filters, failed=True)
        with conn.cursor() as cursor:
            cursor.execute(f'SELECT {FIELDS} FROM overdraft_applications WHERE {where} ORDER BY id LIMIT %s' + (' FOR UPDATE' if lock else ''), (*values,MAX_RECOVERY+1))
            rows=cursor.fetchall()
        if len(rows)>MAX_RECOVERY:
            raise ValueError('More than 500 failed records match. Narrow the filters before preparing recovery.')
        return [{key:str(value) if value is not None else None for key,value in row.items()} for row in rows]

    def preview(self, filters):
        with self.connection() as conn:
            return self.snapshot(conn, filters)

    def apply(self, evidence):
        ids=[row['id'] for row in evidence]
        with self.connection() as conn:
            try:
                # Transactional tables are essential for locks and rollback.
                with conn.cursor() as cursor:
                    cursor.execute("SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='overdraft_applications'")
                    table=cursor.fetchone()
                    if not table or str(table['ENGINE']).upper() != 'INNODB':
                        raise ValueError('Recovery requires an InnoDB source table. No records were changed.')
                if self.snapshot(conn, {'record_ids':ids}, lock=True) != evidence:
                    raise ValueError('Records changed since review. Nothing was requeued; prepare a fresh review.')
                where,values=self.where({'record_ids':ids}, failed=True)
                with conn.cursor() as cursor:
                    cursor.execute(f"UPDATE overdraft_applications SET status_id=31,is_processed='0' WHERE {where}", values)
                    if cursor.rowcount != len(ids):
                        raise ValueError('Recovery count changed. The source transaction was rolled back.')
                conn.commit()
                return len(ids)
            except Exception:
                conn.rollback()
                raise


def csv_cell(value):
    text = '' if value is None else str(value)
    # Treat source text as data when the CSV is opened in a spreadsheet.
    return "'" + text if text.lstrip().startswith(('=', '+', '-', '@')) or text.startswith(('\t','\r','\n')) else text
