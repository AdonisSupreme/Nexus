from datetime import date, datetime, timezone
from decimal import Decimal
from contextlib import nullcontext
from unittest.mock import Mock
import base64

import pytest

from app.nexus.unauthorized_clearing import (
    ClearingAccountBatchRequest,
    ClearingApprovalRequest,
    ClearingOracleGateway,
    ClearingSourceImportRequest,
    ClearingTransactionInput,
    UnauthorizedClearingService,
    _execution_item_evidence,
    build_execution_payload,
    clearing_operating_window,
    parse_finance_source,
    parse_identity_source,
    reconcile_transactions,
    resolve_balance_rows,
    summarize_account_evidence,
    transaction_fingerprint,
)


def make_transaction(**overrides):
    payload = {
        "source_row": 2,
        "entry_date": date(2026, 7, 22),
        "from_account": "100004167974",
        "to_account": "200000000001",
        "currency": "ZWG",
        "rrn": "613506493636",
        "stan": "493636",
        "amount": Decimal("65.00"),
        "charge": Decimal("2.20"),
        "narration": "EcoCash test",
    }
    payload.update(overrides)
    transaction = ClearingTransactionInput(**payload)
    return {**transaction.model_dump(), "fingerprint": transaction_fingerprint(transaction)}


def balance(row_id="DB-ZWG", amount="67.20", currency="ZWG", queue_amount="0"):
    return {
        "row_id": row_id,
        "internal_account": "1102800003627",
        "currency": currency,
        "unauth_db_sum": Decimal(amount),
        "debit_queue_amount": Decimal(queue_amount),
    }


def queue(row_id="Q1", *, flag="D", account_currency="ZWG", transaction_currency="USD"):
    return {
        "row_id": row_id,
        "internal_account": "1102800003627",
        "destination_internal_account": "2200000000001",
        "entry_date": date(2026, 7, 22),
        "rrn": "613506493636",
        "stan": "493636",
        "amount": Decimal("65.00"),
        "fee": Decimal("2.20"),
        "processing_fee": Decimal("0.30"),
        "card_billing_fee": Decimal("0.10"),
        "currency": transaction_currency,
        "account_currency": account_currency,
        "debit_credit_flag": flag,
    }


def oracle_state(*, balances=None, queues=None):
    return {
        "mappings": {"100004167974": ["1102800003627"]},
        "balances": {"1102800003627": balances if balances is not None else [balance()]},
        "queues": {"1102800003627": queues if queues is not None else [queue()]},
    }


def test_finance_csv_import_accepts_optional_destination_and_currency():
    content = (
        "Date,From Account,Currency,RRN,STAN,Amount,Fee,Narration\n"
        "22/07/2026,100004167974,ZWG,613506493636,493636,65.00,2.2,Test\n"
    ).encode()

    rows = parse_finance_source("finance.csv", content)

    assert len(rows) == 1
    assert rows[0].entry_date == date(2026, 7, 22)
    assert rows[0].from_account == "100004167974"
    assert rows[0].to_account == ""
    assert rows[0].currency == "ZWG"
    assert rows[0].amount == Decimal("65.00")
    assert rows[0].charge == Decimal("2.20")


@pytest.mark.parametrize(
    ("kind", "header", "value"),
    [("ACCOUNT", "Account", "100004167974"), ("RRN", "RRN", "180001000436")],
)
def test_identity_import_accepts_one_identifier_column(kind, header, value):
    rows = parse_identity_source("identity.csv", f"{header}\n{value}\n".encode(), kind)

    assert rows == [value]


def test_identity_import_tolerates_whitespace_around_the_header():
    rows = parse_identity_source("identity.csv", b" Account Number \n100004167974\n", "ACCOUNT")

    assert rows == ["100004167974"]


def test_identity_import_rejects_additional_columns():
    with pytest.raises(ValueError, match="one-column file"):
        parse_identity_source("identity.csv", b"Account,Amount\n100004167974,20.00\n", "ACCOUNT")


def test_finance_import_reports_a_missing_stan_column_once_and_cleanly():
    content = (
        "Date,From Account,RRN,Amount,Fee\n"
        "22/07/2026,100004167974,613506493636,65.00,2.20\n"
        "22/07/2026,100004167975,613506493637,10.00,0.00\n"
    ).encode()

    with pytest.raises(ValueError) as error:
        parse_finance_source("finance.csv", content)

    message = str(error.value)
    assert "missing required column(s): STAN" in message
    assert "validation error" not in message
    assert "pydantic.dev" not in message


def test_finance_import_accepts_stan_number_header_alias():
    content = (
        "Transaction Date,Debit Account,Currency,RRN,STAN Number,Transaction Amount,Fee Amount\n"
        "22/07/2026,100004167974,ZWG,613506493636,493636,65.00,2.20\n"
    ).encode()

    rows = parse_finance_source("finance.csv", content)

    assert rows[0].stan == "493636"
    assert rows[0].charge == Decimal("2.20")


def test_live_account_summary_is_debit_only_and_excludes_explicit_credit_queue_rows():
    summary = summarize_account_evidence(
        [
            {"currency": "ZWG", "unauth_db_sum": Decimal("70.00")},
            {"currency": "USD", "unauth_db_sum": Decimal("2.20")},
        ],
        [
            queue(),
            {**queue("Q-CREDIT", flag="C"), "amount": Decimal("999.00")},
        ],
    )

    assert summary == {
        "physical_row_count": 2,
        "queue_row_count": 1,
        "unauthorized_debit_total": "72.20",
        "queued_amount_total": "65.00",
        "queued_fee_total": "2.60",
        "physical_queue_amount_total": "0.00",
        "orphaned_queue_amount_total": "0",
        "currencies": ["USD", "ZWG"],
    }


def test_live_account_summary_surfaces_orphaned_physical_queue_amount():
    summary = summarize_account_evidence(
        [balance(amount="0", queue_amount="75.83")],
        [],
    )

    assert summary["unauthorized_debit_total"] == "0.00"
    assert summary["queue_row_count"] == 0
    assert summary["physical_queue_amount_total"] == "75.83"
    assert summary["orphaned_queue_amount_total"] == "75.83"


def test_live_account_view_is_direct_oracle_evidence_and_is_audited():
    repository = Mock()
    oracle = Mock()
    oracle.inspect_account.return_value = {
        "external_account": "100004167974",
        "internal_accounts": ["1102800003627"],
        "account_profiles": [{"account_name": "Test account"}],
        "mapping_count": 1,
        "balance_rows": [balance()],
        "queue_rows": [queue()],
        "summary": {
            "physical_row_count": 1,
            "queue_row_count": 1,
            "unauthorized_debit_total": "67.20",
            "queued_amount_total": "65.00",
            "queued_fee_total": "2.60",
            "currencies": ["ZWG"],
        },
        "captured_at": "2026-07-29T12:00:00+00:00",
    }

    view = UnauthorizedClearingService(repository=repository, oracle=oracle).live_account_view(
        "100004167974",
        actor="operator.one",
        actor_role="operator",
    )

    assert view["batch_id"] is None
    assert view["source"] == "LIVE_ORACLE"
    assert view["transactions"] == []
    assert view["snapshot"]["account_role"] == "LIVE"
    assert view["snapshot"]["account_profiles"][0]["account_name"] == "Test account"
    repository.record_account_lookup.assert_called_once_with(
        "100004167974",
        actor="operator.one",
        actor_role="operator",
        evidence_summary={
            "mapping_count": 1,
            **oracle.inspect_account.return_value["summary"],
        },
    )


def test_live_rrn_view_resolves_internal_account_without_acnts_and_is_audited():
    repository = Mock()
    oracle = Mock()
    oracle.inspect_rrn.return_value = {
        "external_account": "100008505041",
        "external_accounts": ["100008505041"],
        "lookup_mode": "RRN",
        "lookup_value": "180001000436",
        "internal_accounts": ["1102800003627"],
        "mapping_count": 1,
        "matched_queue_count": 1,
        "balance_rows": [balance()],
        "queue_rows": [{**queue(), "lookup_match": True}],
        "summary": {
            "physical_row_count": 1,
            "queue_row_count": 1,
            "unauthorized_debit_total": "67.20",
            "queued_amount_total": "65.00",
            "queued_fee_total": "2.60",
            "currencies": ["ZWG"],
        },
        "captured_at": "2026-08-14T12:00:00+00:00",
    }

    view = UnauthorizedClearingService(repository=repository, oracle=oracle).live_rrn_view(
        "180001000436",
        actor="operator.one",
        actor_role="operator",
    )

    assert view["lookup_mode"] == "RRN"
    assert view["external_account"] == "100008505041"
    assert view["snapshot"]["external_accounts"] == ["100008505041"]
    assert view["snapshot"]["internal_account"] == "1102800003627"
    assert view["snapshot"]["queue_rows"][0]["lookup_match"] is True
    repository.record_rrn_lookup.assert_called_once_with(
        "180001000436",
        actor="operator.one",
        actor_role="operator",
        evidence_summary={
            "mapping_count": 1,
            "matched_queue_count": 1,
            "internal_accounts": ["1102800003627"],
            "external_accounts": ["100008505041"],
            **oracle.inspect_rrn.return_value["summary"],
        },
    )


def test_rrn_lookup_sql_uses_queue_narration_and_never_depends_on_acnts():
    sql = ClearingOracleGateway.RRN_LOOKUP_SQL.upper()

    assert "BGPQ_TRN_NARR1" in sql
    assert ":RRN_TOKEN" in sql
    assert "BGPQ_INT_ACCT_1" in sql
    assert "FROM ACNTS" not in sql


def test_rrn_reverse_account_sql_uses_internal_account_as_its_authority():
    sql = ClearingOracleGateway.REVERSE_ACCOUNT_SQL.upper()

    assert "FACNO(:ENTITY_NUM, ACNTS_INTERNAL_ACNUM)" in sql
    assert "ACNTS_INTERNAL_ACNUM = :INTERNAL_ACCOUNT" in sql


def test_transaction_fingerprint_is_stable_and_currency_sensitive():
    first = ClearingTransactionInput(**make_transaction())
    equivalent = ClearingTransactionInput(**make_transaction(amount="65", charge="2.200"))
    usd = ClearingTransactionInput(**make_transaction(currency="USD"))

    assert transaction_fingerprint(first) == transaction_fingerprint(equivalent)
    assert transaction_fingerprint(first) != transaction_fingerprint(usd)


def test_zero_value_is_reserved_for_full_row_intake_evidence():
    with pytest.raises(ValueError, match="positive amount"):
        ClearingTransactionInput(**make_transaction(amount="0", clear_amount="0"))

    placeholder = ClearingTransactionInput(
        **make_transaction(
            amount="0",
            clear_amount="0",
            operation_mode="BALANCE_ALL",
        )
    )
    assert placeholder.amount == Decimal("0")


def test_balance_resolution_targets_only_the_selected_currency_partition():
    resolution = resolve_balance_rows(
        [
            balance("DB-USD", "500.00", "USD"),
            balance("DB-ZWG", "200.00", "ZWG"),
        ],
        delta=Decimal("137.40"),
        currency="ZWG",
    )

    assert resolution["state"] == "SAFE"
    assert resolution["row_id"] == "DB-ZWG"
    assert resolution["currency"] == "ZWG"
    assert resolution["after"] == Decimal("62.60")


def test_balance_resolution_blocks_multiple_nonzero_rows_in_one_currency():
    resolution = resolve_balance_rows(
        [balance("AAA", "67.20", "ZWG"), balance("BBB", "67.20", "ZWG")],
        delta=Decimal("67.20"),
        currency="ZWG",
    )

    assert resolution["state"] == "BLOCKED"
    assert resolution["candidate_count"] == 2


def test_reconciliation_uses_account_currency_and_preserves_unapproved_queue_rows():
    transaction = make_transaction()
    state = oracle_state(
        balances=[balance(), balance("DB-USD", "99.00", "USD")],
        queues=[queue(), {**queue("Q-EXTRA"), "rrn": "OTHER", "stan": "999999"}],
    )

    results, snapshots, summary = reconcile_transactions([transaction], state)
    result = results[transaction["fingerprint"]]

    assert result["state"] == "SAFE_EXTRA_QUEUE"
    assert result["currency"] == "ZWG"
    assert result["queue_match"]["transaction_currency"] == "USD"
    assert result["queue_match"]["account_currency"] == "ZWG"
    assert result["debit_resolution"]["row_id"] == "DB-ZWG"
    assert result["extra_queue_count"] == 1
    assert summary["safe_extra_queue"] == 1
    assert snapshots[0]["account_role"] == "DEBIT"


def test_explicit_credit_queue_row_never_authorizes_debit_clearing():
    transaction = make_transaction()
    results, _, summary = reconcile_transactions(
        [transaction],
        oracle_state(queues=[queue(flag="C")]),
    )

    result = results[transaction["fingerprint"]]
    assert result["state"] == "BLOCKED"
    assert result["queue_match"] is None
    assert summary["blocked"] == 1


def test_queue_present_with_zero_balance_requires_special_review():
    transaction = make_transaction()
    results, _, summary = reconcile_transactions(
        [transaction],
        oracle_state(balances=[balance(amount="0")]),
    )

    assert results[transaction["fingerprint"]]["state"] == "SPECIAL_REVIEW"
    assert summary["special_review"] == 1


def test_queue_row_only_reconciliation_is_ready_without_an_unauthorized_debit_mutation():
    transaction = make_transaction(
        operation_mode="QUEUE_ROW_ONLY",
        clear_amount="0",
        queue_row_id="Q1",
    )
    results, _, summary = reconcile_transactions(
        [transaction],
        oracle_state(balances=[balance(amount="0", queue_amount="67.20")]),
    )

    result = results[transaction["fingerprint"]]
    assert result["state"] == "READY"
    assert result["delete_queue"] is True
    assert result["debit_resolution"]["state"] == "NOT_REQUIRED"
    assert summary["ready"] == 1


def test_orphaned_queue_amount_reconciliation_targets_only_the_queue_column():
    transaction = make_transaction(
        amount="75.83",
        charge="0",
        clear_amount="0",
        operation_mode="QUEUE_AMOUNT_RESET",
        rrn="QAM-TEST",
        stan="QATEST",
    )
    results, _, summary = reconcile_transactions(
        [transaction],
        oracle_state(
            balances=[balance(amount="0", queue_amount="75.83")],
            queues=[],
        ),
    )

    result = results[transaction["fingerprint"]]
    assert result["state"] == "READY"
    assert result["debit_resolution"]["column"] == "ACNTBAL_AC_DB_QUEUE_AMT"
    assert result["debit_resolution"]["after"] == "0.00"
    assert summary["ready"] == 1

    ready = {
        "batch_id": "batch-queue-repair",
        "finance_reference": "QUEUE-REPAIR",
        "source_sha256": "b" * 64,
        "transactions": [
            {
                **transaction,
                "selected": True,
                "reconciliation_state": "READY",
                "reconciliation_payload": result,
            }
        ],
    }
    payload = build_execution_payload(ready, "CHG-QUEUE-1", "Repair orphaned queue amount")
    assert payload["balance_mutations"][0]["column"] == "ACNTBAL_AC_DB_QUEUE_AMT"
    assert payload["balance_mutations"][0]["role"] == "QUEUE"
    assert payload["queue_deletions"] == []


def test_reconciliation_blocks_two_transactions_competing_for_one_queue_row():
    first = make_transaction()
    second = make_transaction(source_row=3, to_account="200000000002")

    results, _, summary = reconcile_transactions(
        [first, second],
        oracle_state(balances=[balance(amount="134.40")]),
    )

    assert results[first["fingerprint"]]["state"] == "BLOCKED"
    assert results[second["fingerprint"]]["state"] == "BLOCKED"
    assert summary["blocked"] == 2
    assert "same live queue row" in results[first["fingerprint"]]["blockers"][0]


def test_reconciliation_aggregates_multiple_queue_rows_against_one_physical_debit():
    source = [
        ("Q1", "033115777669", "051007", "30.00", "5.00"),
        ("Q2", "000266423301", "051002", "40.00", "5.00"),
        ("Q3", "033115773000", "051005", "39.00", "5.00"),
    ]
    transactions = []
    queue_rows = []
    for source_row, (row_id, rrn, stan, amount, charge) in enumerate(source, start=1):
        transactions.append(
            make_transaction(
                source_row=source_row,
                rrn=rrn,
                stan=stan,
                amount=amount,
                charge=charge,
                clear_amount=str(Decimal(amount) + Decimal(charge)),
                operation_mode="QUEUE_EXACT",
                queue_row_id=row_id,
            )
        )
        queue_rows.append(
            {
                **queue(row_id),
                "rrn": rrn,
                "stan": stan,
                "amount": Decimal(amount),
                "fee": Decimal(charge),
            }
        )

    results, _, summary = reconcile_transactions(
        transactions,
        oracle_state(balances=[balance(amount="124.00")], queues=queue_rows),
    )

    assert summary["ready"] == 3
    assert {result["state"] for result in results.values()} == {"READY"}
    assert {result["debit_resolution"]["delta"] for result in results.values()} == {"124.00"}
    assert {result["debit_resolution"]["after"] for result in results.values()} == {"0.00"}


def ready_batch(*, operation_mode="QUEUE_EXACT", delete_queue=True, clear_amount="67.20"):
    transaction = make_transaction(operation_mode=operation_mode, clear_amount=clear_amount)
    transaction["selected"] = True
    transaction["reconciliation_state"] = "READY"
    transaction["reconciliation_payload"] = {
        "debit_resolution": {
            "state": "SAFE",
            "row_id": "DB-ZWG",
            "column": "ACNTBAL_AC_UNAUTH_DB_SUM",
            "internal_account": "1102800003627",
            "currency": "ZWG",
            "current": "100.00",
            "delta": clear_amount,
            "after": str(Decimal("100.00") - Decimal(clear_amount)),
        },
        "currency": "ZWG",
        "clear_amount": clear_amount,
        "delete_queue": delete_queue,
        "queue_match": {
            "row_id": "Q1",
            "internal_account": "1102800003627",
            "entry_date": "2026-07-22",
            "rrn": "613506493636",
            "stan": "493636",
            "amount": "65.00",
            "charge": "2.20",
            "currency": "ZWG",
            "account_currency": "ZWG",
        },
    }
    if operation_mode == "BALANCE_ALL":
        transaction["reconciliation_payload"]["queue_match"] = None
    return {
        "batch_id": "batch-1",
        "finance_reference": "FIN-001",
        "source_sha256": "a" * 64,
        "transactions": [transaction],
    }


def test_execution_payload_contains_one_currency_bound_debit_mutation():
    batch = ready_batch()
    batch["latest_reconciliation"] = {"reconciliation_id": "reconciliation-1"}
    payload = build_execution_payload(batch, "CHG-001", "Approved list")

    assert payload["payload_hash"]
    assert payload["reconciliation_id"] == "reconciliation-1"
    assert len(payload["balance_mutations"]) == 1
    assert payload["balance_mutations"][0]["role"] == "DEBIT"
    assert payload["balance_mutations"][0]["currency"] == "ZWG"
    assert payload["queue_deletions"][0]["row_id"] == "Q1"


def test_execution_payload_collapses_multi_queue_authority_into_one_physical_mutation():
    rows = [
        ("Q1", "033115777669", "051007", "30.00", "5.00"),
        ("Q2", "000266423301", "051002", "40.00", "5.00"),
        ("Q3", "033115773000", "051005", "39.00", "5.00"),
    ]
    transactions = []
    for source_row, (row_id, rrn, stan, amount, charge) in enumerate(rows, start=1):
        transaction = make_transaction(
            source_row=source_row,
            rrn=rrn,
            stan=stan,
            amount=amount,
            charge=charge,
            clear_amount=str(Decimal(amount) + Decimal(charge)),
            operation_mode="QUEUE_EXACT",
            queue_row_id=row_id,
        )
        transaction.update(
            selected=True,
            reconciliation_state="READY",
            reconciliation_payload={
                "debit_resolution": {
                    "state": "SAFE",
                    "row_id": "DB-ZWG",
                    "column": "ACNTBAL_AC_UNAUTH_DB_SUM",
                    "internal_account": "1102800003627",
                    "currency": "ZWG",
                    "current": "124.00",
                    "delta": "124.00",
                    "after": "0.00",
                },
                "currency": "ZWG",
                "clear_amount": str(Decimal(amount) + Decimal(charge)),
                "delete_queue": True,
                "queue_match": {
                    "row_id": row_id,
                    "internal_account": "1102800003627",
                    "entry_date": "2026-07-22",
                    "rrn": rrn,
                    "stan": stan,
                    "amount": amount,
                    "charge": charge,
                    "currency": "ZWG",
                    "account_currency": "ZWG",
                },
            },
        )
        transactions.append(transaction)

    payload = build_execution_payload(
        {
            "batch_id": "multi-queue-batch",
            "finance_reference": "FIN-MULTI",
            "source_sha256": "b" * 64,
            "latest_reconciliation": {"reconciliation_id": "reconciliation-multi"},
            "transactions": transactions,
        },
        "CHG-MULTI",
        "Approved multi-row queue authority",
    )

    assert len(payload["balance_mutations"]) == 1
    assert payload["balance_mutations"][0]["delta"] == "124.00"
    assert {item["row_id"] for item in payload["queue_deletions"]} == {"Q1", "Q2", "Q3"}


def test_execution_item_evidence_is_scoped_to_its_sealed_transaction():
    payload = {
        "transactions": [
            {"fingerprint": "fingerprint-a", "from_account": "1001", "currency": "USD"},
            {"fingerprint": "fingerprint-b", "from_account": "1002", "currency": "ZWG"},
        ]
    }
    evidence = {
        "balance_mutations": [
            {"row_id": "BAL-A", "external_account": "1001", "currency": "USD"},
            {"row_id": "BAL-B", "external_account": "1002", "currency": "ZWG"},
        ],
        "queue_deletions": [
            {"row_id": "QUEUE-A", "fingerprint": "fingerprint-a"},
            {"row_id": "QUEUE-B", "fingerprint": "fingerprint-b"},
        ],
        "before": {
            "balance_rows": {
                "BAL-A": {"row_id": "BAL-A", "unauth_db_sum": "10.00"},
                "BAL-B": {"row_id": "BAL-B", "unauth_db_sum": "20.00"},
            },
            "queue_rows": {
                "QUEUE-A": {"row_id": "QUEUE-A", "rrn": "RRN-A"},
                "QUEUE-B": {"row_id": "QUEUE-B", "rrn": "RRN-B"},
            },
        },
        "after": {"deleted_queue_row_ids": ["QUEUE-A", "QUEUE-B"]},
    }

    projected = _execution_item_evidence(payload, evidence)

    assert list(projected["fingerprint-a"]["before"]["balance_rows"]) == ["BAL-A"]
    assert list(projected["fingerprint-a"]["before"]["queue_rows"]) == ["QUEUE-A"]
    assert projected["fingerprint-a"]["after"]["deleted_queue_row_ids"] == ["QUEUE-A"]
    assert list(projected["fingerprint-b"]["before"]["balance_rows"]) == ["BAL-B"]


@pytest.mark.parametrize("mode", ["QUEUE_PARTIAL", "BALANCE_ALL"])
def test_partial_and_full_row_payloads_preserve_queue_records(mode):
    payload = build_execution_payload(
        ready_batch(operation_mode=mode, delete_queue=False, clear_amount="25.00"),
        "CHG-002",
        "Controlled debit",
    )

    assert payload["balance_mutations"][0]["delta"] == "25.00"
    assert payload["queue_deletions"] == []


def test_execution_payload_rejects_special_review_selection():
    batch = ready_batch()
    batch["transactions"][0]["reconciliation_state"] = "SPECIAL_REVIEW"

    with pytest.raises(ValueError, match="Only safely reconciled"):
        build_execution_payload(batch, "CHG-001", "")


@pytest.mark.parametrize(
    ("hour", "minute", "blocked"),
    [(7, 59, False), (8, 0, True), (18, 59, True), (19, 0, False)],
)
def test_business_hour_window_boundaries(hour, minute, blocked):
    instant = datetime(2026, 8, 14, hour - 2, minute, tzinfo=timezone.utc)
    assert clearing_operating_window(instant)["blocked"] is blocked


def test_large_source_remains_available_when_only_one_command_tranche_is_armed():
    repository = Mock()
    repository.get_batch.return_value = {
        "transaction_count": 42,
        "transactions": [
            {"selected": index < 20, "custody_state": "PENDING"}
            for index in range(42)
        ],
    }
    service = UnauthorizedClearingService(
        repository=repository,
        oracle=Mock(),
        clock=lambda: datetime(2026, 8, 14, 10, 0, tzinfo=timezone.utc),
    )

    batch = service._assert_batch_window_open("batch-1")

    assert batch["transaction_count"] == 42


def test_command_scope_rejects_more_than_twenty_armed_pending_records():
    repository = Mock()
    repository.get_batch.return_value = {
        "transaction_count": 42,
        "transactions": [
            {"selected": index < 21, "custody_state": "PENDING"}
            for index in range(42)
        ],
    }
    service = UnauthorizedClearingService(repository=repository, oracle=Mock())

    with pytest.raises(ValueError, match="active command tranche exceeds 20 records"):
        service._assert_batch_window_open("batch-1")


def test_small_batches_remain_available_during_business_hours():
    repository = Mock()
    repository.get_batch.return_value = {
        "transaction_count": 20,
        "transactions": [
            {"selected": True, "custody_state": "PENDING"}
            for _ in range(20)
        ],
    }
    service = UnauthorizedClearingService(
        repository=repository,
        oracle=Mock(),
        clock=lambda: datetime(2026, 8, 14, 10, 0, tzinfo=timezone.utc),
    )

    assert service._assert_batch_window_open("batch-1")["transaction_count"] == 20


def test_account_identity_import_prepares_each_positive_currency_row_for_full_debit_verification():
    repository = Mock()
    repository.create_batch.return_value = {"batch_id": "identity-batch"}
    oracle = Mock()
    oracle.collect.return_value = {
        "mappings": {"100004167974": ["1102800003627"]},
        "balances": {
            "1102800003627": [
                balance(amount="67.20", currency="ZWG"),
                balance(row_id="DB-USD", amount="10.00", currency="USD"),
            ]
        },
        "queues": {"1102800003627": []},
    }
    service = UnauthorizedClearingService(repository=repository, oracle=oracle)
    source = b"Account\n100004167974\n"

    result = service.import_source(
        ClearingSourceImportRequest(
            batch_name="Account identity batch",
            finance_reference="FIN-IDENTITY-1",
            filename="accounts.csv",
            content_base64=base64.b64encode(source).decode(),
            identity_kind="ACCOUNT",
        ),
        actor="maker",
        actor_role="operator",
    )

    assert result["batch_id"] == "identity-batch"
    request = repository.create_batch.call_args.args[0]
    assert request.source_kind == "IDENTITY_IMPORT"
    assert {item.currency for item in request.transactions} == {"ZWG", "USD"}
    assert all(item.operation_mode == "BALANCE_ALL" for item in request.transactions)
    oracle.collect.assert_called_once_with({"100004167974"}, set())
    oracle.inspect_account.assert_not_called()


def test_account_identity_import_keeps_zero_debit_accounts_for_batch_verification():
    repository = Mock()
    repository.create_batch.return_value = {"batch_id": "identity-batch"}
    oracle = Mock()
    oracle.collect.return_value = {
        "mappings": {"100004167974": ["1102800003627"]},
        "balances": {"1102800003627": [balance(amount="0.00", currency="ZWG")]},
        "queues": {"1102800003627": []},
    }
    service = UnauthorizedClearingService(repository=repository, oracle=oracle)

    service.import_source(
        ClearingSourceImportRequest(
            batch_name="Account identity batch",
            finance_reference="FIN-IDENTITY-ZERO",
            filename="accounts.csv",
            content_base64=base64.b64encode(b"Account\n100004167974\n").decode(),
            identity_kind="ACCOUNT",
        ),
        actor="maker",
        actor_role="operator",
    )

    transaction = repository.create_batch.call_args.args[0].transactions[0]
    assert transaction.amount == Decimal("0")
    assert transaction.clear_amount == Decimal("0")
    assert transaction.operation_mode == "BALANCE_ALL"
    assert "No positive unauthorized debit" in transaction.narration


def test_account_identity_import_seals_every_row_when_oracle_is_temporarily_unavailable():
    repository = Mock()
    repository.create_batch.return_value = {"batch_id": "identity-batch"}
    oracle = Mock()
    oracle.collect.side_effect = RuntimeError("DPY-6000: listener refused connection")
    service = UnauthorizedClearingService(repository=repository, oracle=oracle)

    service.import_source(
        ClearingSourceImportRequest(
            batch_name="Account identity batch",
            finance_reference="FIN-IDENTITY-DEFERRED",
            filename="accounts.csv",
            content_base64=base64.b64encode(
                b"Account\n100004167974\n100004167975\n"
            ).decode(),
            identity_kind="ACCOUNT",
        ),
        actor="maker",
        actor_role="operator",
    )

    transactions = repository.create_batch.call_args.args[0].transactions
    assert [item.from_account for item in transactions] == ["100004167974", "100004167975"]
    assert all(item.amount == Decimal("0") for item in transactions)
    assert all("Oracle verification pending" in item.narration for item in transactions)


def test_rrn_identity_import_requires_one_exact_debit_queue_row():
    repository = Mock()
    repository.get_specific_record_policy.return_value = {"enabled": True}
    repository.create_batch.return_value = {"batch_id": "rrn-identity-batch"}
    oracle = Mock()
    oracle.inspect_rrn.return_value = {
        "mapping_count": 1,
        "internal_accounts": ["1102800003627"],
        "external_account": "100004167974",
        "queue_rows": [{**queue(), "lookup_match": True}],
    }
    service = UnauthorizedClearingService(repository=repository, oracle=oracle)

    service.import_source(
        ClearingSourceImportRequest(
            batch_name="RRN identity batch",
            finance_reference="FIN-IDENTITY-2",
            filename="rrns.csv",
            content_base64=base64.b64encode(b"RRN\n613506493636\n").decode(),
            identity_kind="RRN",
        ),
        actor="maker",
        actor_role="operator",
    )

    transaction = repository.create_batch.call_args.args[0].transactions[0]
    assert transaction.operation_mode == "QUEUE_EXACT"
    assert transaction.queue_row_id == "Q1"
    assert transaction.source_internal_account == "1102800003627"


def test_account_explorer_creates_currency_bound_partial_batch_without_writing_oracle():
    repository = Mock()
    repository.get_specific_record_policy.return_value = {"enabled": True}
    repository.create_batch.return_value = {"batch_id": "account-batch"}
    oracle = Mock()
    oracle.inspect_account.return_value = {
        "mapping_count": 1,
        "balance_rows": [balance(amount="100.00")],
        "queue_rows": [queue()],
    }
    service = UnauthorizedClearingService(repository=repository, oracle=oracle)

    created = service.create_account_batch(
        "100004167974",
        ClearingAccountBatchRequest(
            balance_row_id="DB-ZWG",
            currency="ZWG",
            mode="QUEUE_TRANSACTION",
            queue_row_id="Q1",
            clear_amount="25.00",
            change_reference="CHG-ACCOUNT-1",
            note="Operator-authorized partial debit release",
        ),
        actor="maker",
        actor_role="operator",
    )

    assert created["batch_id"] == "account-batch"
    request = repository.create_batch.call_args.args[0]
    assert request.source_kind == "ACCOUNT_EXPLORER"
    assert request.transactions[0].currency == "ZWG"
    assert request.transactions[0].operation_mode == "QUEUE_PARTIAL"
    assert request.transactions[0].clear_amount == Decimal("25.00")
    assert request.transactions[0].to_account == ""
    assert not hasattr(oracle, "execute_atomic") or not oracle.execute_atomic.called


def test_account_explorer_seals_multiple_queue_rows_against_one_physical_debit():
    repository = Mock()
    repository.get_specific_record_policy.return_value = {"enabled": True}
    repository.create_batch.return_value = {"batch_id": "multi-queue-batch"}
    queue_rows = [
        {**queue("Q1"), "rrn": "033115777669", "stan": "051007", "amount": Decimal("30.00"), "fee": Decimal("5.00")},
        {**queue("Q2"), "rrn": "000266423301", "stan": "051002", "amount": Decimal("40.00"), "fee": Decimal("5.00")},
        {**queue("Q3"), "rrn": "033115773000", "stan": "051005", "amount": Decimal("39.00"), "fee": Decimal("5.00")},
    ]
    oracle = Mock()
    oracle.inspect_account.return_value = {
        "mapping_count": 1,
        "balance_rows": [balance(amount="124.00")],
        "queue_rows": queue_rows,
    }
    service = UnauthorizedClearingService(repository=repository, oracle=oracle)

    created = service.create_account_batch(
        "100004167974",
        ClearingAccountBatchRequest(
            balance_row_id="DB-ZWG",
            currency="ZWG",
            mode="QUEUE_TRANSACTION",
            queue_row_ids=["Q1", "Q2", "Q3"],
            clear_amount="124.00",
            change_reference="CHG-MULTI-QUEUE",
            note="Three queue rows support one physical balance",
        ),
        actor="maker",
        actor_role="operator",
    )

    assert created["batch_id"] == "multi-queue-batch"
    request = repository.create_batch.call_args.args[0]
    assert [item.queue_row_id for item in request.transactions] == ["Q1", "Q2", "Q3"]
    assert all(item.operation_mode == "QUEUE_EXACT" for item in request.transactions)
    assert sum((item.clear_amount for item in request.transactions), Decimal("0")) == Decimal("124.00")


def test_rrn_account_explorer_batch_preserves_direct_internal_account_binding():
    repository = Mock()
    repository.get_specific_record_policy.return_value = {"enabled": True}
    repository.create_batch.return_value = {"batch_id": "rrn-account-batch"}
    oracle = Mock()
    oracle.inspect_rrn.return_value = {
        "mapping_count": 1,
        "matched_queue_count": 1,
        "internal_accounts": ["1102800003627"],
        "balance_rows": [balance(amount="100.00")],
        "queue_rows": [{**queue(), "lookup_match": True}],
    }
    service = UnauthorizedClearingService(repository=repository, oracle=oracle)

    created = service.create_rrn_batch(
        "180001000436",
        ClearingAccountBatchRequest(
            balance_row_id="DB-ZWG",
            currency="ZWG",
            mode="QUEUE_TRANSACTION",
            queue_row_id="Q1",
            clear_amount="25.00",
            change_reference="CHG-RRN-1",
            note="RRN-authorized partial debit release",
        ),
        actor="maker",
        actor_role="operator",
    )

    assert created["batch_id"] == "rrn-account-batch"
    request = repository.create_batch.call_args.args[0]
    transaction = request.transactions[0]
    assert transaction.from_account == "1102800003627"
    assert transaction.source_internal_account == "1102800003627"
    assert transaction.operation_mode == "QUEUE_PARTIAL"
    assert request.source_filename == "rrn-180001000436.json"


def test_direct_internal_mapping_reconciles_without_an_external_account_lookup():
    transaction = make_transaction(
        from_account="1102800003627",
        source_internal_account="1102800003627",
    )
    state = oracle_state()
    state["mappings"] = {"1102800003627": ["1102800003627"]}

    results, snapshots, _ = reconcile_transactions([transaction], state)

    result = results[transaction["fingerprint"]]
    assert result["state"] == "READY"
    assert result["from_mapping"]["locator_type"] == "ASIBGPQNP_RRN"
    assert snapshots[0]["internal_account"] == "1102800003627"


def test_operator_specific_record_clearing_obeys_admin_policy():
    repository = Mock()
    repository.get_specific_record_policy.return_value = {"enabled": False}
    service = UnauthorizedClearingService(repository=repository, oracle=Mock())

    with pytest.raises(ValueError, match="Specific-record clearing is disabled"):
        service._assert_specific_record_allowed(actor_role="operator")

    service._assert_specific_record_allowed(actor_role="admin")


def test_checker_approval_starts_and_completes_the_sealed_mutation():
    repository = Mock()
    repository.get_batch.return_value = {"transaction_count": 1, "transactions": [{}]}
    repository.action_lock.return_value = nullcontext()
    repository.approve_and_start_execution.return_value = {
        "execution_id": "execution-1",
        "status": "CREATED",
        "payload_hash": "payload-hash",
        "approved_payload": {"payload_hash": "payload-hash", "transactions": []},
    }
    repository.finish_execution.return_value = {
        "execution_id": "execution-1",
        "status": "COMMITTED",
    }
    oracle = Mock()
    oracle.execute_atomic.return_value = {"mutations": [], "queue_deletions": []}
    service = UnauthorizedClearingService(repository=repository, oracle=oracle)

    result = service.approve(
        "batch-1",
        ClearingApprovalRequest(
            approve=True,
            note="Reviewed against Finance authority",
            idempotency_key="approval-batch-1",
        ),
        actor="checker.one",
        actor_role="operator",
    )

    assert result["status"] == "COMMITTED"
    repository.approve_and_start_execution.assert_called_once_with(
        "batch-1",
        actor="checker.one",
        actor_role="operator",
        note="Reviewed against Finance authority",
        idempotency_key="approval-batch-1",
        allow_self_approval=False,
    )
    oracle.execute_atomic.assert_called_once()


def test_admin_approval_is_the_only_self_approval_exception():
    repository = Mock()
    repository.get_batch.return_value = {"transaction_count": 1, "transactions": [{}]}
    repository.action_lock.return_value = nullcontext()
    repository.approve_and_start_execution.return_value = {
        "execution_id": "execution-2",
        "status": "CREATED",
        "payload_hash": "payload-hash",
        "approved_payload": {"payload_hash": "payload-hash", "transactions": []},
    }
    repository.finish_execution.return_value = {
        "execution_id": "execution-2",
        "status": "COMMITTED",
    }
    service = UnauthorizedClearingService(repository=repository, oracle=Mock())

    service.approve(
        "batch-1",
        ClearingApprovalRequest(
            approve=True,
            note="Administrative emergency custody approval",
            idempotency_key="approval-admin-batch-1",
        ),
        actor="custody.admin",
        actor_role="admin",
    )

    assert repository.approve_and_start_execution.call_args.kwargs["allow_self_approval"] is True


def test_rejected_payload_never_starts_oracle_mutation():
    repository = Mock()
    repository.decide_approval.return_value = {"batch_id": "batch-1", "status": "READY_FOR_APPROVAL"}
    oracle = Mock()
    service = UnauthorizedClearingService(repository=repository, oracle=oracle)

    result = service.approve(
        "batch-1",
        ClearingApprovalRequest(approve=False, note="Return for corrected Finance scope"),
        actor="checker.one",
        actor_role="operator",
    )

    assert result["status"] == "READY_FOR_APPROVAL"
    repository.decide_approval.assert_called_once_with(
        "batch-1",
        approve=False,
        actor="checker.one",
        actor_role="operator",
        note="Return for corrected Finance scope",
        allow_self_approval=False,
    )
    repository.approve_and_start_execution.assert_not_called()
    oracle.execute_atomic.assert_not_called()
