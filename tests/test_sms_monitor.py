from contextlib import contextmanager
from datetime import datetime
from unittest.mock import MagicMock
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from app.nexus import sms_monitor as module
from app.nexus.sms_monitor import SmsMonitor, scope_sql
from app.api.sms_monitor import router
from app.access.middleware import ModuleAccessMiddleware
from app.access.policy import required_modules
from app.utils.sentinelops_auth import require_nexus_access


def fake_gateway(rows):
    gateway, cursor = SmsMonitor(), MagicMock()
    cursor.fetchall.return_value = rows
    @contextmanager
    def connection():
        yield cursor
    gateway.connection = connection
    return gateway, cursor


def test_scope_keeps_email_deleted_out_and_parameterizes_input():
    sql, args = scope_sql(status='ERROR', source="x' OR true --", search="x' OR true --", hours=24, aged=True, before=123)
    assert "channel = 'SMS' AND deleted IS NOT TRUE" in sql
    assert "x' OR true" not in sql
    assert args == ['ERROR', "x' OR true --", "x' OR true --", 24, 123]
    assert "status IN ('QUEUED','RETRYABLE')" in sql
    assert 'id < %s' in sql
    with pytest.raises(ValueError): scope_sql(status='EMAIL')
    with pytest.raises(ValueError): scope_sql(hours=7)


def test_numeric_lookup_uses_bigint_and_preserves_recipient_string():
    sql, args = scope_sql(search='263000000263')
    assert 'id = %s' in sql and 'id::text' not in sql
    assert args == [263000000263, '263000000263']
    assert scope_sql(search='999999999999999999999999999999')[1] == ['999999999999999999999999999999']


def test_records_are_masked_bounded_keyset_pages_with_lossless_ids(monkeypatch):
    monkeypatch.setattr(module.settings, 'SMSAL_TIMEZONE', 'Africa/Harare')
    rows = [dict(id=9007199254740999-i, recipients='263000000263', created_at=datetime(2026,10,28,10), status='QUEUED') for i in range(51)]
    gateway, cursor = fake_gateway(rows)
    result = gateway.records()
    assert len(result['items']) == 50
    assert result['items'][0]['id'] == '9007199254740999'
    assert result['items'][0]['created_at'] == '2026-10-28T08:00:00+00:00'
    assert result['items'][0]['recipients'].endswith('0263')
    assert '263000000263' not in str(result)
    assert result['next_cursor'] == result['items'][-1]['id']
    assert 'ORDER BY id DESC LIMIT 51' in cursor.execute.call_args.args[0]
    assert 'message' not in cursor.execute.call_args.args[0]


def test_detail_never_reads_email_or_deleted_records_and_handles_archival():
    gateway, cursor = fake_gateway([])
    cursor.fetchone.return_value = None
    with pytest.raises(LookupError, match='archived'):
        gateway.detail(9731710)
    sql, args = cursor.execute.call_args.args
    assert "channel = 'SMS' AND deleted IS NOT TRUE AND id=%s" in sql
    assert args == (9731710,)
    assert 'email_data' not in sql and 'template_data' not in sql


def test_connection_forces_read_only_and_query_timeouts(monkeypatch):
    import psycopg
    for key,value in {'SMSAL_HOST':'test.invalid','SMSAL_USERNAME':'reader','SMSAL_PASSWORD':SecretStr('test-only'),'SMSAL_TIMEZONE':'Africa/Harare'}.items():
        monkeypatch.setattr(module.settings,key,value)
    connect = MagicMock()
    monkeypatch.setattr(psycopg, 'connect', connect)
    with SmsMonitor().connection(): pass
    assert 'default_transaction_read_only=on' in connect.call_args.kwargs['options']
    assert 'statement_timeout=8000' in connect.call_args.kwargs['options']
    cursor = connect.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value
    assert cursor.execute.call_args_list[0].args[0].endswith('READ ONLY')
    assert cursor.execute.call_args_list[1].args[1] == ('Africa/Harare',)


def test_overview_coalesces_reads_and_reports_retained_not_delivery_rates(monkeypatch):
    monkeypatch.setattr(SmsMonitor, 'configured', property(lambda _: True))
    monkeypatch.setattr(module,'_overview_cache',None)
    monkeypatch.setattr(module,'_overview_until',0)
    gateway, cursor = fake_gateway([])
    cursor.fetchone.return_value = {'retained':8, 'queued':3, 'retryable':2, 'errors':1, 'sent':2}
    first = gateway.overview()
    second = gateway.overview()
    assert first == second and cursor.execute.call_count == 3
    assert first['configured'] and first['observed_at']
    for call in cursor.execute.call_args_list:
        assert "channel = 'SMS' AND deleted IS NOT TRUE" in call.args[0]
        assert not any(word in call.args[0] for word in ('UPDATE public', 'DELETE FROM', 'INSERT INTO'))


def client(keys, monkeypatch):
    app = FastAPI()
    user = {'id':'user', 'role':'USER', 'access':{'modules':keys}}
    async def authenticate(_=None): return user
    app.dependency_overrides[require_nexus_access] = authenticate
    app.add_middleware(ModuleAccessMiddleware, authenticate=authenticate, connect=lambda: None)
    app.include_router(router, prefix='/api/v1')
    monkeypatch.setattr(SmsMonitor,'overview',lambda _: {'configured':False})
    return TestClient(app)


def test_sms_module_is_required_not_general_reporting(monkeypatch):
    assert required_modules('/api/v1/nexus/reports/sms/records/1') == ('reports.sms',)
    assert client(['reports.personal_loans'],monkeypatch).get('/api/v1/nexus/reports/sms/overview').status_code == 403
    allowed = client(['reports.sms'],monkeypatch)
    assert allowed.get('/api/v1/nexus/reports/sms/overview').status_code == 200
    assert allowed.post('/api/v1/nexus/reports/sms/overview').status_code == 405
    assert allowed.get('/api/v1/nexus/reports/sms/records/99999999999999999999999').status_code == 400


def test_database_errors_never_expose_connection_secrets(monkeypatch):
    api = client(['reports.sms'],monkeypatch)
    def broken(_): raise RuntimeError('password=secret host=private')
    monkeypatch.setattr(SmsMonitor,'overview',broken)
    response = api.get('/api/v1/nexus/reports/sms/overview')
    assert response.status_code == 503
    assert 'secret' not in response.text and 'private' not in response.text
