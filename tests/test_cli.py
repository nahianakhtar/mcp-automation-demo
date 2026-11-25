"""CLI tests for recon_mcp.cli using cli.main([...]) and capsys under tmp_path."""

from __future__ import annotations

import csv
import hashlib
import sys
import types
from pathlib import Path

import pytest

from recon_mcp import cli
from recon_mcp.guards import Policy
from recon_mcp.models import AuditEvent, ExportResult, ReconReport


def _read_audit_events(audit_path: Path) -> list[AuditEvent]:
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    return [AuditEvent.model_validate_json(line) for line in lines if line.strip()]


def _write_matching_csvs(tmp_path: Path) -> tuple[Path, Path]:
    inv_path = tmp_path / "matched_invoices.csv"
    exp_path = tmp_path / "matched_expenses.csv"
    inv_path.write_text(
        "id,date,counterparty,amount,currency,reference\n"
        "INV-10,2026-02-01,Alpha Co,100.00,USD,REF-10\n"
        "INV-11,2026-02-02,Beta Co,250.50,USD,\n",
        encoding="utf-8",
    )
    exp_path.write_text(
        "id,date,counterparty,amount,currency,reference\n"
        "EXP-10,2026-02-01,Alpha Co,100.00,USD,REF-10\n"
        "EXP-11,2026-02-03,beta co,250.50,USD,\n",
        encoding="utf-8",
    )
    return inv_path, exp_path


def test_cli_reconcile_all_matched_exit_0_and_json(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    inv_path, exp_path = _write_matching_csvs(tmp_path)
    audit_path = tmp_path / ".recon" / "audit.jsonl"

    code = cli.main(
        [
            "reconcile",
            "--invoices",
            str(inv_path),
            "--expenses",
            str(exp_path),
            "--json",
            "--audit-log",
            str(audit_path),
        ]
    )

    captured = capsys.readouterr()
    assert code == 0
    assert captured.err == ""

    report = ReconReport.model_validate_json(captured.out)
    assert len(report.matched) == 2
    assert report.unmatched_invoices == []
    assert report.unmatched_expenses == []
    assert report.totals.delta == "0.00"

    events = _read_audit_events(audit_path)
    assert len(events) == 1
    ev = events[0]
    assert ev.actor == "cli"
    assert ev.tool == "reconcile"
    assert ev.mode == "read"
    assert ev.dry_run is False
    assert ev.outcome == "ok"
    assert str(inv_path.resolve()) in ev.inputs_sha256
    assert str(exp_path.resolve()) in ev.inputs_sha256
    assert ev.result_sha256 == hashlib.sha256(captured.out.strip().encode("utf-8")).hexdigest()

    audit_text = audit_path.read_text(encoding="utf-8")
    assert "100.00" not in audit_text
    assert "250.50" not in audit_text
    assert "Alpha Co" not in audit_text


def test_cli_reconcile_unmatched_exit_1_csv_and_sqlite(
    tmp_path: Path,
    fixtures_dir: Path,
    ledger_db: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    audit_path = tmp_path / "audit.jsonl"

    csv_code = cli.main(
        [
            "reconcile",
            "--invoices",
            str(fixtures_dir / "invoices.csv"),
            "--expenses",
            str(fixtures_dir / "expenses.csv"),
            "--audit-log",
            str(audit_path),
        ]
    )
    csv_cap = capsys.readouterr()
    assert csv_code == 1
    assert "matched=3" in csv_cap.out
    assert "unmatched_invoices=2" in csv_cap.out
    assert "unmatched_expenses=2" in csv_cap.out
    assert csv_cap.err == ""

    db_code = cli.main(
        [
            "reconcile",
            "--invoices",
            str(ledger_db),
            "--expenses",
            str(ledger_db),
            "--table-invoices",
            "invoices",
            "--table-expenses",
            "expenses",
            "--json",
            "--audit-log",
            str(audit_path),
        ]
    )
    db_cap = capsys.readouterr()
    assert db_code == 1
    report = ReconReport.model_validate_json(db_cap.out)
    assert len(report.matched) == 3
    assert len(report.unmatched_invoices) == 2
    assert len(report.unmatched_expenses) == 2

    events = _read_audit_events(audit_path)
    assert len(events) == 2
    assert all(ev.outcome == "ok" and ev.tool == "reconcile" for ev in events)


def test_cli_reconcile_usage_and_input_errors_exit_2_and_audit(
    tmp_path: Path,
    ledger_db: Path,
    fixtures_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("RECON_AUDIT_LOG", str(audit_path))

    missing_args_code = cli.main(["reconcile"])
    err1 = capsys.readouterr()
    assert missing_args_code == 2
    assert err1.out == ""
    assert err1.err != ""

    no_table_code = cli.main(
        [
            "reconcile",
            "--invoices",
            str(ledger_db),
            "--expenses",
            str(fixtures_dir / "expenses.csv"),
        ]
    )
    err2 = capsys.readouterr()
    assert no_table_code == 2
    assert "table" in err2.err.lower()

    bad_tol_code = cli.main(
        [
            "reconcile",
            "--invoices",
            str(fixtures_dir / "invoices.csv"),
            "--expenses",
            str(fixtures_dir / "expenses.csv"),
            "--tolerance",
            "not-a-number",
        ]
    )
    err3 = capsys.readouterr()
    assert bad_tol_code == 2
    assert err3.err != ""

    events = _read_audit_events(audit_path)
    assert len(events) == 3
    assert all(ev.outcome == "error" and ev.actor == "cli" for ev in events)


def test_cli_reconcile_read_root_escape_exit_3(
    tmp_path: Path,
    fixtures_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    read_root = tmp_path / "inputs"
    read_root.mkdir()
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("RECON_READ_ROOT", str(read_root))

    code = cli.main(
        [
            "reconcile",
            "--invoices",
            str(fixtures_dir / "invoices.csv"),
            "--expenses",
            str(fixtures_dir / "expenses.csv"),
            "--audit-log",
            str(audit_path),
        ]
    )
    captured = capsys.readouterr()
    assert code == 3
    assert captured.out == ""
    assert "read_root" in captured.err

    events = _read_audit_events(audit_path)
    assert len(events) == 1
    assert events[0].outcome == "denied"


def test_cli_export_denied_write_exit_3(
    tmp_path: Path,
    fixtures_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("RECON_ALLOW_WRITE", raising=False)
    write_root = tmp_path / "out"
    audit_path = tmp_path / "audit.jsonl"

    denied_code = cli.main(
        [
            "export",
            "--invoices",
            str(fixtures_dir / "invoices.csv"),
            "--expenses",
            str(fixtures_dir / "expenses.csv"),
            "--out",
            "report.json",
            "--apply",
            "--write-root",
            str(write_root),
            "--audit-log",
            str(audit_path),
        ]
    )
    cap1 = capsys.readouterr()
    assert denied_code == 3
    assert cap1.out == ""
    assert "does not allow writes" in cap1.err
    assert not (write_root / "report.json").exists()

    traversal_code = cli.main(
        [
            "export",
            "--invoices",
            str(fixtures_dir / "invoices.csv"),
            "--expenses",
            str(fixtures_dir / "expenses.csv"),
            "--out",
            "../escape.json",
            "--allow-write",
            "--apply",
            "--write-root",
            str(write_root),
            "--audit-log",
            str(audit_path),
        ]
    )
    cap2 = capsys.readouterr()
    assert traversal_code == 3
    assert cap2.out == ""
    assert "escapes write_root" in cap2.err
    assert not (tmp_path / "escape.json").exists()

    events = _read_audit_events(audit_path)
    assert len(events) == 2
    assert all(
        ev.tool == "export" and ev.mode == "write" and ev.outcome == "denied" for ev in events
    )
    assert events[0].dry_run is False


def test_cli_export_dry_run_default_and_audit(
    tmp_path: Path,
    fixtures_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("RECON_ALLOW_WRITE", raising=False)
    write_root = tmp_path / "out"
    audit_path = tmp_path / "audit.jsonl"

    code = cli.main(
        [
            "export",
            "--invoices",
            str(fixtures_dir / "invoices.csv"),
            "--expenses",
            str(fixtures_dir / "expenses.csv"),
            "--out",
            "report.json",
            "--write-root",
            str(write_root),
            "--json",
            "--audit-log",
            str(audit_path),
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert captured.err == ""

    result = ExportResult.model_validate_json(captured.out)
    assert result.written is False
    assert result.path == str((write_root / "report.json").resolve())
    assert result.rows == 7
    assert not write_root.exists()
    assert not Path(result.path).exists()

    events = _read_audit_events(audit_path)
    assert len(events) == 1
    ev = events[0]
    assert ev.tool == "export"
    assert ev.mode == "write"
    assert ev.dry_run is True
    assert ev.outcome == "ok"
    assert ev.result_sha256 == result.sha256


def test_cli_export_applied_json_and_csv_and_no_overwrite(
    tmp_path: Path,
    fixtures_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    write_root = tmp_path / "out"
    audit_path = tmp_path / "audit.jsonl"

    json_code = cli.main(
        [
            "export",
            "--invoices",
            str(fixtures_dir / "invoices.csv"),
            "--expenses",
            str(fixtures_dir / "expenses.csv"),
            "--out",
            "report.json",
            "--allow-write",
            "--apply",
            "--write-root",
            str(write_root),
            "--json",
            "--audit-log",
            str(audit_path),
        ]
    )
    cap1 = capsys.readouterr()
    assert json_code == 0
    assert cap1.err == ""

    json_res = ExportResult.model_validate_json(cap1.out)
    assert json_res.written is True
    json_path = Path(json_res.path)
    assert json_path.is_file()
    original_bytes = json_path.read_bytes()
    assert hashlib.sha256(original_bytes).hexdigest() == json_res.sha256
    report = ReconReport.model_validate_json(original_bytes.decode("utf-8"))
    assert len(report.matched) == 3

    overwrite_code = cli.main(
        [
            "export",
            "--invoices",
            str(fixtures_dir / "invoices.csv"),
            "--expenses",
            str(fixtures_dir / "expenses.csv"),
            "--out",
            "report.json",
            "--allow-write",
            "--apply",
            "--write-root",
            str(write_root),
            "--audit-log",
            str(audit_path),
        ]
    )
    cap2 = capsys.readouterr()
    assert overwrite_code == 3
    assert "overwrite" in cap2.err.lower()
    assert json_path.read_bytes() == original_bytes

    monkeypatch.setenv("RECON_ALLOW_WRITE", "1")
    csv_code = cli.main(
        [
            "export",
            "--invoices",
            str(fixtures_dir / "invoices.csv"),
            "--expenses",
            str(fixtures_dir / "expenses.csv"),
            "--out",
            "nested/report.csv",
            "--apply",
            "--write-root",
            str(write_root),
            "--json",
            "--audit-log",
            str(audit_path),
        ]
    )
    cap3 = capsys.readouterr()
    assert csv_code == 0
    csv_res = ExportResult.model_validate_json(cap3.out)
    assert csv_res.written is True
    csv_path = Path(csv_res.path)
    assert hashlib.sha256(csv_path.read_bytes()).hexdigest() == csv_res.sha256
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.reader(handle))
    assert len(rows) == csv_res.rows + 1

    events = _read_audit_events(audit_path)
    assert [ev.outcome for ev in events] == ["ok", "denied", "ok"]
    assert events[0].dry_run is False
    assert events[0].result_sha256 == json_res.sha256
    assert events[2].result_sha256 == csv_res.sha256

    audit_text = audit_path.read_text(encoding="utf-8")
    assert "1250.00" not in audit_text
    assert "Acme Corp" not in audit_text


def test_cli_serve_invokes_server_with_policy_and_no_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    write_root = tmp_path / "out"
    audit_path = tmp_path / "audit.jsonl"
    recorded: dict[str, object] = {}

    class _StubServer:
        def run(self, transport: str = "stdio") -> None:
            recorded["transport"] = transport

    def fake_build_server(policy: Policy) -> _StubServer:
        recorded["policy"] = policy
        return _StubServer()

    stub_module = types.ModuleType("recon_mcp.server")
    stub_module.build_server = fake_build_server  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "recon_mcp.server", stub_module)

    code = cli.main(
        [
            "serve",
            "--allow-write",
            "--write-root",
            str(write_root),
            "--audit-log",
            str(audit_path),
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert captured.out == ""
    assert captured.err == ""
    assert recorded["transport"] == "stdio"
    assert recorded["policy"] == Policy(
        allow_write=True,
        write_root=write_root,
        read_root=None,
        audit_log=audit_path,
    )

    events = _read_audit_events(audit_path)
    assert len(events) == 1
    assert events[0].actor == "cli"
    assert events[0].tool == "serve"
    assert events[0].mode == "write"
    assert events[0].outcome == "ok"


def test_cli_help_writes_audit_event(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    audit_path = tmp_path / "audit.jsonl"
    code = cli.main(["--audit-log", str(audit_path), "--help"])
    captured = capsys.readouterr()
    assert code == 0
    assert "reconcile" in captured.out

    events = _read_audit_events(audit_path)
    assert len(events) == 1
    assert events[0].tool == "help"
    assert events[0].outcome == "ok"
