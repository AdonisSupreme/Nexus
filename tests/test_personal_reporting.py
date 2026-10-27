from contextlib import contextmanager
from unittest.mock import MagicMock
import csv
import io

import pytest

from app.nexus.personal_loans import PersonalLoanGateway, EXPORT_LIMIT
from app.access.policy import required_modules


def gateway_with_rows(rows):
    gateway = PersonalLoanGateway()
    conn = MagicMock()
    cursor = conn.cursor.return_value.__enter__.return_value
    cursor.fetchall.return_value = rows
    @contextmanager
    def connection():
        yield conn
    gateway.connection = connection
    return gateway, cursor, conn


def test_legacy_scope_is_explicit_parameterized_and_keeps_failed_guard():
    sql, values = PersonalLoanGateway().where({'currency':'USD','maturity_after':'2029-12-31','pay_from':'2025-06-01', 'branch':"1' OR 1=1"}, failed=True)
    assert "STR_TO_DATE(maturity, '%%Y-%%m-%%d') > %s" in sql
    assert "STR_TO_DATE(next_pay_date, '%%Y-%%m-%%d') >= %s" in sql
    assert "1' OR 1=1" not in sql
    assert 18 in values and '2' in values
    assert str(values[-2]) == '2029-12-31' and str(values[-1]) == '2025-06-01'
    assert 'STR_TO_DATE' not in PersonalLoanGateway().where({})[0]


def test_processed_period_uses_processed_not_created_and_normalizes_timezone():
    sql, values = PersonalLoanGateway().where({'date_basis':'processed','created_from':'2026-10-23T00:00:00+02:00','created_to':'2026-10-24T00:00:00+02:00'})
    assert 'processed_datetime >= %s' in sql and 'processed_datetime < %s' in sql
    assert 'created_at >=' not in sql
    assert values[-1] > values[-2]


@pytest.mark.parametrize('filters', [{'date_basis':'x; DROP TABLE'}, {'maturity_after':'invalid'}, {'pay_from':'2026-10-25','pay_to':'2026-10-23'}])
def test_invalid_scope_never_reaches_source(filters):
    with pytest.raises(ValueError):
        PersonalLoanGateway().where(filters)


def test_export_scopes_all_pages_and_escapes_formulas_without_identity_documents():
    gateway, cursor, conn = gateway_with_rows([{'id':1,'full_name':' =HYPERLINK("bad")','bot_message':'line 1\nline 2','approved_amount':'123.45'}])
    content = gateway.export_csv({'status':'SUCCESS','currency':'ZWL'})
    rows = list(csv.DictReader(io.StringIO(content.lstrip('\ufeff'))))
    assert rows[0]['full_name'].startswith("'")
    assert rows[0]['bot_message'] == 'line 1\nline 2'
    assert rows[0]['approved_amount'] == '123.45'
    assert 'national_id_number' not in rows[0]
    assert 'OFFSET' not in cursor.execute.call_args.args[0]
    assert cursor.execute.call_args.args[1][-1] == EXPORT_LIMIT+1
    assert 'ZWL PERSONAL LOAN 48 MONTHS' in cursor.execute.call_args.args[1]
    conn.commit.assert_not_called()


def test_export_refuses_truncation():
    gateway, _, _ = gateway_with_rows([{}]*(EXPORT_LIMIT+1))
    with pytest.raises(ValueError, match='10,000'):
        gateway.export_csv({})


def test_report_groups_currency_and_state_and_has_no_source_mutations():
    gateway, cursor, conn = gateway_with_rows([])
    result = gateway.report({'date_basis':'processed'})
    queries = [call.args[0] for call in cursor.execute.call_args_list]
    assert 'GROUP BY overdraft_tenure,status_id,is_processed' in queries[0]
    assert 'DATE(processed_datetime)' in queries[1]
    assert result['export_limit'] == 10000 and result['recovery_limit'] == 500
    conn.commit.assert_not_called()


@pytest.mark.parametrize('suffix',['report','export'])
def test_report_routes_require_personal_loan_access(suffix):
    assert required_modules('/api/v1/nexus/reports/personal-loans/'+suffix) == ('reports.personal_loans',)
