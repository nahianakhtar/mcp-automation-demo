"""Unit tests for JSONL audit logging, fsync, injectable clock, and privacy."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from recon_mcp.audit import AuditLog, sha256_file
from recon_mcp.models import AuditEvent


def test_audit_log_writes_jsonl_with_injectable_clock_and_fsync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    log_path = tmp_path / "nested" / "audit.jsonl"
    timestamps = iter(
        [
            datetime(2026, 11, 25, 10, 0, 0, tzinfo=UTC),
            datetime(2026, 11, 25, 6, 30, 0, tzinfo=timezone(timedelta(hours=-5))),
        ]
    )

    fsync_fds: list[int] = []
    real_fsync = os.fsync

    def spy_fsync(fd: int) -> None:
        fsync_fds.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", spy_fsync)

    in_path = tmp_path / "in.csv"
    ex_path = str(tmp_path / "ex.csv")
    out_path = str(tmp_path / "out" / "report.json")

    audit = AuditLog(log_path, now=lambda: next(timestamps))
    ev1 = audit.record(
        actor="cli",
        tool="reconcile",
        mode="read",
        dry_run=False,
        outcome="ok",
        args={"invoices": in_path, "expenses": ex_path, "window_days": 3},
        inputs_sha256={"invoices": "a" * 64, "expenses": "b" * 64},
        result_sha256="c" * 64,
    )
    ev2 = audit.record(
        actor="mcp",
        tool="export_report",
        mode="write",
        dry_run=False,
        outcome="denied",
        args={"out": out_path, "apply": True},
        error="Write denied",
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert len(fsync_fds) == 2

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2

    raw1 = json.loads(lines[0])
    assert raw1 == {
        "ts": "2026-11-25T10:00:00Z",
        "actor": "cli",
        "tool": "reconcile",
        "mode": "read",
        "dry_run": False,
        "args": {"invoices": str(in_path), "expenses": ex_path, "window_days": 3},
        "inputs_sha256": {"invoices": "a" * 64, "expenses": "b" * 64},
        "outcome": "ok",
        "error": None,
        "result_sha256": "c" * 64,
    }
    assert ev1 == AuditEvent.model_validate(raw1)

    raw2 = json.loads(lines[1])
    assert raw2["ts"] == "2026-11-25T11:30:00Z"
    assert raw2["outcome"] == "denied"
    assert raw2["error"] == "Write denied"
    assert ev2 == AuditEvent.model_validate(raw2)


def test_audit_log_never_logs_amounts_or_row_contents(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    audit = AuditLog(log_path, now=lambda: datetime(2026, 1, 1, tzinfo=UTC))

    audit.record(
        actor="mcp",
        tool="reconcile",
        mode="read",
        dry_run=False,
        outcome="ok",
        args={
            "invoices": "invoices.csv",
            "expenses": "expenses.csv",
            "tolerance": "0.05",
            "amount": "98765.43",
            "amounts": ["1234.56"],
            "rows": [{"counterparty": "Secret Co", "amount": "55555.00"}],
            "counterparty": "Secret Co",
        },
    )

    direct_event = AuditEvent(
        ts="2026-01-01T00:00:00Z",
        actor="cli",
        tool="export",
        mode="write",
        dry_run=True,
        args={"out": "out/r.json", "amount": "77777.88", "totals": "99999.00"},
        outcome="error",
        error="failed",
    )
    audit.append(direct_event)

    text = log_path.read_text(encoding="utf-8")
    for forbidden in ("98765.43", "1234.56", "55555.00", "77777.88", "99999.00", "Secret Co"):
        assert forbidden not in text
    assert "tolerance" not in text
    assert "amounts" not in text
    assert "totals" not in text


def test_audit_tail_and_validation(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    audit = AuditLog(log_path, now=lambda: datetime(2026, 1, 1, tzinfo=UTC))

    assert audit.tail() == []

    for idx in range(5):
        audit.record(
            actor="cli",
            tool=f"tool-{idx}",
            mode="read",
            dry_run=False,
            outcome="ok",
        )

    last_two = audit.tail(2)
    assert [ev.tool for ev in last_two] == ["tool-3", "tool-4"]

    for bad_n in (0, -1, 201, True):
        with pytest.raises(ValueError, match="between 1 and 200"):
            audit.tail(bad_n)


def test_sha256_file(tmp_path: Path) -> None:
    sample = tmp_path / "sample.csv"
    payload = b"id,date,counterparty,amount,currency,reference\n1,2026-01-01,A,10.00,USD,R1\n"
    sample.write_bytes(payload)

    assert sha256_file(sample) == hashlib.sha256(payload).hexdigest()
