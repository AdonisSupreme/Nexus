from contextlib import nullcontext
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock
from zoneinfo import ZoneInfo

from app.nexus.crb_reporting import CRB_REPORTS, CRBReportingService


class FakeCursor:
    def __init__(self, rows):
        self.rows = list(rows)
        self.offset = 0
        self.arraysize = 0
        self.prefetchrows = 0
        self.query = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, query):
        self.query = query

    def fetchmany(self, size):
        chunk = self.rows[self.offset:self.offset + size]
        self.offset += len(chunk)
        return chunk


class FakeConnection:
    def __init__(self, rows):
        self.cursor_instance = FakeCursor(rows)

    def cursor(self):
        return self.cursor_instance


def test_report_contracts_preserve_the_approved_view_names_and_column_counts():
    assert [(spec.view_name, len(spec.fields)) for spec in CRB_REPORTS] == [
        ("VW_CONTRACT_DATA", 32),
        ("LMS_INDCLT_DETAILS", 57),
    ]
    assert CRB_REPORTS[0].fields[0] == "SUBSCRIBERCODE"
    assert CRB_REPORTS[0].fields[-1] == "SNO"
    assert CRB_REPORTS[1].fields[0] == "BUSINESSDATE"
    assert CRB_REPORTS[1].fields[-1] == "CURRENCYOFCONTRACT"


def test_extract_writes_the_view_named_csv_with_exact_header(tmp_path, monkeypatch):
    service = CRBReportingService(repository=Mock(), oracle=Mock())
    service.report_dir = tmp_path
    spec = CRB_REPORTS[0]
    row = tuple("" if index == 1 else f"value-{index}" for index in range(len(spec.fields)))
    connection = FakeConnection([row])
    monkeypatch.setattr("app.nexus.crb_reporting.settings.NEXUS_CRB_FETCH_SIZE", 100)

    metadata = service._extract_one(connection, spec)

    target = Path(metadata["storage_path"])
    lines = target.read_text(encoding="utf-8").splitlines()
    assert target.name == "VW_CONTRACT_DATA.csv"
    assert lines[0].split(",") == list(spec.fields)
    assert metadata["row_count"] == 1
    assert connection.cursor_instance.query == f"SELECT {', '.join(spec.fields)} FROM VW_CONTRACT_DATA"


def test_scheduler_boundary_rolls_to_the_next_day_after_0715(monkeypatch, tmp_path):
    repository = Mock()
    oracle = Mock()
    service = CRBReportingService(repository=repository, oracle=oracle)
    service.report_dir = tmp_path
    zone = ZoneInfo("Africa/Harare")
    monkeypatch.setattr("app.nexus.crb_reporting.settings.NEXUS_CRB_SCHEDULE_TIME", "07:15")
    monkeypatch.setattr("app.nexus.crb_reporting.settings.NEXUS_CRB_TIMEZONE", "Africa/Harare")

    before = service.next_schedule_at(datetime(2026, 8, 21, 7, 14, tzinfo=zone))
    after = service.next_schedule_at(datetime(2026, 8, 21, 7, 15, tzinfo=zone))

    assert before.isoformat() == "2026-08-21T07:15:00+02:00"
    assert after.isoformat() == "2026-08-22T07:15:00+02:00"


def test_successful_run_extracts_both_views_and_records_both_artifacts(tmp_path):
    repository = Mock()
    repository.extraction_lock.return_value = nullcontext()
    repository.begin_run.return_value = {
        "run_id": "run-1",
        "trigger": "MANUAL",
        "requested_by": "operator.one",
    }
    repository.finish_run.return_value = {"run_id": "run-1", "status": "COMPLETED"}
    oracle = Mock()
    oracle.connection.return_value = nullcontext(FakeConnection([]))
    service = CRBReportingService(repository=repository, oracle=oracle)
    service.report_dir = tmp_path

    result = service.execute_run("run-1")

    assert result["status"] == "COMPLETED"
    assert [call.args[1].view_name for call in repository.save_artifact.call_args_list] == [
        "VW_CONTRACT_DATA",
        "LMS_INDCLT_DETAILS",
    ]
    assert (tmp_path / "VW_CONTRACT_DATA.csv").is_file()
    assert (tmp_path / "LMS_INDCLT_DETAILS.csv").is_file()
