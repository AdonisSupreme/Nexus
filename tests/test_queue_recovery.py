from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, Mock

import pytest

from app.nexus.queue_recovery import HoveringRecoveryGateway, QueueRecovery
from app.nexus.personal_loans import PersonalLoanGateway, TENURES
from app.access.policy import required_modules


@contextmanager
def connection(value):
    yield value


def test_loan_ledger_filter_is_always_failed_and_scoped():
    gateway = HoveringRecoveryGateway(dsn='unused')
    sql, values = gateway.where({'description': '', 'lookup': "' OR 1=1 --"})
    assert "status = 'FAILED'" in sql
    assert 'credit_account = %s' in sql and 'type = %s' in sql
    assert "BTRIM(COALESCE(description, '')) = %s" in sql
    assert "OR 1=1" not in sql
    assert '' in values


def test_empty_id_list_cannot_turn_into_all_records():
    with pytest.raises(ValueError):
        HoveringRecoveryGateway(dsn='unused').where({'record_ids': []})
    with pytest.raises(ValueError):
        PersonalLoanGateway().where({'record_ids': []}, failed=True)


def test_personal_queue_scopes_exact_tenures_and_failed_state():
    sql, values = PersonalLoanGateway().where({'record_ids': ['156713']}, failed=True)
    assert values[:2] == list(TENURES)
    assert values[2:4] == [18, '2']
    assert 'id IN (%s)' in sql
    assert 'status_id=%s' in sql and 'is_processed=%s' in sql


@pytest.mark.parametrize('currency', ['USD', 'ZWL'])
def test_currency_filters_exact_tenure_even_when_source_currency_field_is_missing(currency):
    sql, values = PersonalLoanGateway().where({'currency':currency}, failed=True)
    assert 'overdraft_tenure=%s' in sql
    assert f'{currency} PERSONAL LOAN 48 MONTHS' in values
    assert values[-2:] == [18, '2']


def test_unknown_currency_is_rejected():
    with pytest.raises(ValueError, match='USD'):
        PersonalLoanGateway().where({'currency':'EUR'})


def test_personal_ids_reject_non_numeric_and_oversized_selection():
    for ids in [["1 OR 1=1"], [str(i) for i in range(501)]]:
        with pytest.raises(ValueError):
            PersonalLoanGateway().where({'record_ids': ids}, failed=True)


def test_preview_refuses_more_than_500():
    conn = Mock()
    conn.execute.return_value.fetchall.return_value = [{'id': str(i)} for i in range(501)]
    with pytest.raises(ValueError, match='500'):
        HoveringRecoveryGateway(dsn='unused').snapshot(conn, {})


def test_changed_evidence_never_updates_source():
    gateway = HoveringRecoveryGateway(dsn='unused')
    conn = Mock()
    gateway.connection = lambda: connection(conn)
    gateway.snapshot = Mock(return_value=[])
    with pytest.raises(ValueError, match='changed'):
        gateway.apply([{'id': '1', 'status':'FAILED'}])
    conn.execute.assert_not_called()
    conn.commit.assert_not_called()


def test_ledger_recovery_updates_status_only():
    gateway = HoveringRecoveryGateway(dsn='unused')
    conn = Mock()
    conn.execute.return_value.rowcount = 1
    evidence = [{'id':'1', 'status':'FAILED'}]
    gateway.connection = lambda: connection(conn)
    gateway.snapshot = Mock(return_value=evidence)
    assert gateway.apply(evidence) == 1
    sql = conn.execute.call_args.args[0]
    assert "SET status = 'PENDING' WHERE" in sql
    assert 'installment_date =' not in sql and 'description =' not in sql
    assert "status = 'FAILED'" in sql
    conn.commit.assert_called_once()


def recovery_with_action(state='PREPARED', expired=False):
    conn = Mock()
    conn.execute.return_value.fetchone.return_value = {
        'state':state, 'expires_at':datetime.now(timezone.utc) + timedelta(minutes=-1 if expired else 5),
        'evidence':[{'id':'1'}],
    }
    repository = Mock()
    repository._connection = lambda: connection(conn)
    gateway = Mock()
    service = QueueRecovery(gateway=gateway, repository=repository)
    service.finish = Mock()
    return service, conn, gateway


@pytest.mark.parametrize('state,expired', [('COMPLETED',False),('APPLYING',False),('UNCERTAIN',False),('PREPARED',True)])
def test_duplicate_or_expired_execution_never_reaches_source(state, expired):
    service, _, gateway = recovery_with_action(state, expired)
    with pytest.raises(ValueError):
        service.execute('action', 'operator')
    gateway.apply.assert_not_called()


def test_intent_is_committed_before_source_mutation():
    service, conn, gateway = recovery_with_action()
    def apply(_):
        conn.commit.assert_called_once()
        assert any("state='APPLYING'" in call.args[0] for call in conn.execute.call_args_list)
        return 1
    gateway.apply.side_effect = apply
    assert service.execute('action','operator')['updated_count'] == 1
    service.finish.assert_called_once_with('action','COMPLETED',1)


def test_connection_failure_is_uncertain_not_retryable():
    service, _, gateway = recovery_with_action()
    gateway.apply.side_effect = OSError('lost connection')
    with pytest.raises(ValueError, match='uncertain'):
        service.execute('action','operator')
    service.finish.assert_called_once_with('action','UNCERTAIN',0)


def test_custody_unavailable_prevents_source_update():
    service, conn, gateway = recovery_with_action()
    conn.commit.side_effect = OSError('custody unavailable')
    with pytest.raises(OSError):
        service.execute('action','operator')
    gateway.apply.assert_not_called()


def test_personal_recovery_requires_transactional_table():
    gateway=PersonalLoanGateway()
    conn=MagicMock()
    conn.cursor.return_value.__enter__.return_value.fetchone.return_value={'ENGINE':'MyISAM'}
    gateway.connection=lambda: connection(conn)
    with pytest.raises(ValueError, match='InnoDB'):
        gateway.apply([{'id':'1'}])
    conn.rollback.assert_called_once()
    conn.commit.assert_not_called()


def test_personal_recovery_only_changes_two_fields():
    gateway=PersonalLoanGateway()
    conn=MagicMock()
    cursor=conn.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value={'ENGINE':'InnoDB'}
    cursor.rowcount=1
    evidence=[{'id':'1'}]
    gateway.connection=lambda: connection(conn)
    gateway.snapshot=Mock(return_value=evidence)
    assert gateway.apply(evidence)==1
    sql=cursor.execute.call_args.args[0]
    assert "SET status_id=31,is_processed='0' WHERE" in sql
    assert cursor.execute.call_args.args[1][:4] == [*TENURES,18,'2']
    conn.commit.assert_called_once()


@pytest.mark.parametrize('suffix', ['overview','records','failure-reasons','custody','recovery/prepare','recovery/abc/execute'])
def test_personal_loan_routes_require_their_own_module(suffix):
    assert required_modules('/api/v1/nexus/reports/personal-loans/' + suffix) == ('reports.personal_loans',)
