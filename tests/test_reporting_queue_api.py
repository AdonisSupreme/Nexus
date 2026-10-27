from types import SimpleNamespace
from unittest.mock import Mock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.nexus_reports import router
from app.utils.sentinelops_auth import require_nexus_access


def client():
    app = FastAPI()
    app.include_router(router)
    service = Mock()
    service.records.return_value = {'items': []}
    service.overview.return_value = {'date_actions':[{'actor':'private'}], 'policy_audit':[{'actor':'private'}]}
    app.state.services = SimpleNamespace(hovering_monitor=service)
    app.dependency_overrides[require_nexus_access] = lambda: {'username':'operator','role':'USER'}
    return TestClient(app), service


def test_explicit_empty_status_reaches_gateway_as_all():
    api, service = client()
    assert api.get('/nexus/reports/hovering/records?status=').status_code == 200
    assert service.records.call_args.kwargs['status_filter'] is None
    api.get('/nexus/reports/hovering/records')
    assert service.records.call_args.kwargs['status_filter'] == 'PENDING'


def test_blank_failure_description_is_not_dropped():
    api, service = client()
    assert api.get('/nexus/reports/hovering/records?status=FAILED&description=').status_code == 200
    assert service.records.call_args.kwargs['description'] == ''


def test_non_admin_overview_does_not_disclose_custody():
    api, _ = client()
    body = api.get('/nexus/reports/hovering/overview').json()
    assert body['date_actions'] == [] and body['policy_audit'] == []


def test_non_admin_cannot_browse_either_custody_endpoint(monkeypatch):
    async def operator(_):
        return {'username':'operator','role':'USER'}
    monkeypatch.setattr('app.utils.sentinelops_auth.get_current_sentinelops_user', operator)
    api, _ = client()
    for queue in ['hovering','personal-loans']:
        assert api.get(f'/nexus/reports/{queue}/custody').status_code == 403


def test_empty_explicit_selection_rejected_before_preparation():
    api, _ = client()
    for queue in ['hovering','personal-loans']:
        assert api.post(f'/nexus/reports/{queue}/recovery/prepare', json={'record_ids':[]}).status_code == 422

def test_personal_report_and_export_preserve_scope(monkeypatch):
    gateway = Mock()
    gateway.report.return_value = {'groups': [], 'activity': []}
    gateway.export_csv.return_value = '\ufeffid,approved_amount\r\n1,2.00\r\n'
    monkeypatch.setattr('app.api.nexus_reports.PersonalLoanGateway', lambda: gateway)
    api, _ = client()
    params = {'currency':'USD','status':'SUCCESS','date_basis':'processed','branch':'1049','maturity_after':'2029-12-31','pay_from':'2025-06-01'}
    assert api.get('/nexus/reports/personal-loans/report', params=params).status_code == 200
    scope = gateway.report.call_args.args[0]
    for key, value in params.items():
        assert scope[key] == value
    response = api.get('/nexus/reports/personal-loans/export', params=params)
    assert response.status_code == 200
    assert response.headers['cache-control'] == 'no-store'
    assert 'attachment;' in response.headers['content-disposition']
    assert gateway.export_csv.call_args.args[0] == scope
    assert api.get('/nexus/reports/personal-loans/export?date_basis=unsafe').status_code == 422


def test_personal_recovery_retains_reporting_boundaries(monkeypatch):
    recovery = Mock()
    recovery.prepare.return_value = {'count': 1}
    monkeypatch.setattr('app.api.nexus_reports.QueueRecovery', lambda *args: recovery)
    api, _ = client()
    payload = {'currency':'USD','date_basis':'processed','maturity_after':'2029-12-31','pay_from':'2025-06-01','branch':'1049'}
    assert api.post('/nexus/reports/personal-loans/recovery/prepare',json=payload).status_code == 200
    for key, value in payload.items():
        assert recovery.prepare.call_args.args[0][key] == value
