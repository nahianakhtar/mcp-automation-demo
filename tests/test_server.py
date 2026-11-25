"""In-process and stdio-subprocess MCP Client tests for recon_mcp.server."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters

from recon_mcp.guards import Policy
from recon_mcp.models import AuditEvent, ExportResult, ReconReport, SourceInfo
from recon_mcp.server import build_server


def _read_audit_events(audit_path: Path) -> list[AuditEvent]:
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    return [AuditEvent.model_validate_json(line) for line in lines if line.strip()]


@pytest.mark.anyio
async def test_server_list_tools_and_annotations(tmp_policy: Policy) -> None:
    async with Client(build_server(tmp_policy)) as client:
        listed = await client.list_tools()

    by_name = {tool.name: tool for tool in listed.tools}
    assert set(by_name) == {"inspect_source", "reconcile", "export_report", "audit_tail"}

    for read_tool in ("inspect_source", "reconcile", "audit_tail"):
        ann = by_name[read_tool].annotations
        assert ann is not None
        assert ann.read_only_hint is True
        assert ann.open_world_hint is False

    export_ann = by_name["export_report"].annotations
    assert export_ann is not None
    assert export_ann.read_only_hint is False
    assert export_ann.destructive_hint is False
    assert export_ann.idempotent_hint is True
    assert export_ann.open_world_hint is False


@pytest.mark.anyio
async def test_server_inspect_source_and_reconcile_structured_content(
    tmp_policy: Policy,
    fixtures_dir: Path,
    ledger_db: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    inv_csv = fixtures_dir / "invoices.csv"
    exp_csv = fixtures_dir / "expenses.csv"

    async with Client(build_server(tmp_policy)) as client:
        csv_info_res = await client.call_tool("inspect_source", {"path": str(inv_csv)})
        assert csv_info_res.is_error is False
        assert csv_info_res.structured_content is not None
        csv_info = SourceInfo.model_validate(csv_info_res.structured_content)
        assert csv_info.kind == "csv"
        assert csv_info.rows == 5
        assert csv_info.columns == [
            "id",
            "date",
            "counterparty",
            "amount",
            "currency",
            "reference",
        ]

        sql_info_res = await client.call_tool(
            "inspect_source",
            {"path": str(ledger_db), "table": "invoices"},
        )
        assert sql_info_res.is_error is False
        sql_info = SourceInfo.model_validate(sql_info_res.structured_content)
        assert sql_info.kind == "sqlite"
        assert sql_info.rows == 5

        inj_res = await client.call_tool(
            "inspect_source",
            {"path": str(ledger_db), "table": "invoices; DROP TABLE invoices"},
        )
        assert inj_res.is_error is True

        csv_rec_res = await client.call_tool(
            "reconcile",
            {"invoices": str(inv_csv), "expenses": str(exp_csv)},
        )
        assert csv_rec_res.is_error is False
        assert csv_rec_res.structured_content is not None
        assert isinstance(csv_rec_res.structured_content["matched"][0]["amount_delta"], str)
        csv_report = ReconReport.model_validate(csv_rec_res.structured_content)
        assert len(csv_report.matched) == 3
        assert len(csv_report.unmatched_invoices) == 2
        assert len(csv_report.unmatched_expenses) == 2

        sql_rec_res = await client.call_tool(
            "reconcile",
            {
                "invoices": str(ledger_db),
                "expenses": str(ledger_db),
                "table_invoices": "invoices",
                "table_expenses": "expenses",
            },
        )
        assert sql_rec_res.is_error is False
        sql_report = ReconReport.model_validate(sql_rec_res.structured_content)
        assert sql_report == csv_report

        bad_tol_res = await client.call_tool(
            "reconcile",
            {"invoices": str(inv_csv), "expenses": str(exp_csv), "tolerance": "bad"},
        )
        assert bad_tol_res.is_error is True

    captured = capsys.readouterr()
    assert captured.out == ""

    events = _read_audit_events(tmp_policy.audit_log)
    assert len(events) == 6
    assert all(ev.actor == "mcp" for ev in events)
    assert [ev.outcome for ev in events] == ["ok", "ok", "error", "ok", "ok", "error"]

    audit_text = tmp_policy.audit_log.read_text(encoding="utf-8")
    assert "1250.00" not in audit_text
    assert "Acme Corp" not in audit_text


@pytest.mark.anyio
async def test_server_export_report_guardrails_dry_run_and_apply(
    tmp_path: Path,
    fixtures_dir: Path,
) -> None:
    inv_csv = fixtures_dir / "invoices.csv"
    exp_csv = fixtures_dir / "expenses.csv"
    write_root = tmp_path / "out"
    audit_log = tmp_path / "audit.jsonl"

    ro_policy = Policy(allow_write=False, write_root=write_root, audit_log=audit_log)
    async with Client(build_server(ro_policy)) as ro_client:
        dry_res = await ro_client.call_tool(
            "export_report",
            {"invoices": str(inv_csv), "expenses": str(exp_csv), "out": "report.json"},
        )
        assert dry_res.is_error is False
        dry_export = ExportResult.model_validate(dry_res.structured_content)
        assert dry_export.written is False
        assert dry_export.rows == 7
        assert not write_root.exists()
        assert not Path(dry_export.path).exists()

        denied_res = await ro_client.call_tool(
            "export_report",
            {
                "invoices": str(inv_csv),
                "expenses": str(exp_csv),
                "out": "report.json",
                "apply": True,
            },
        )
        assert denied_res.is_error is True
        assert denied_res.structured_content is None
        assert not (write_root / "report.json").exists()

    events_after_ro = _read_audit_events(audit_log)
    assert [ev.outcome for ev in events_after_ro] == ["ok", "denied"]
    assert events_after_ro[0].dry_run is True
    assert events_after_ro[1].dry_run is False
    assert events_after_ro[1].mode == "write"

    rw_policy = Policy(allow_write=True, write_root=write_root, audit_log=audit_log)
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    write_root.mkdir()
    symlink_dir = write_root / "link_out"
    symlink_dir.symlink_to(outside_dir)

    async with Client(build_server(rw_policy)) as rw_client:
        json_res = await rw_client.call_tool(
            "export_report",
            {
                "invoices": str(inv_csv),
                "expenses": str(exp_csv),
                "out": "report.json",
                "apply": True,
            },
        )
        assert json_res.is_error is False
        json_export = ExportResult.model_validate(json_res.structured_content)
        assert json_export.written is True
        json_path = Path(json_export.path)
        assert json_path.is_file()
        original_bytes = json_path.read_bytes()
        assert hashlib.sha256(original_bytes).hexdigest() == json_export.sha256

        overwrite_res = await rw_client.call_tool(
            "export_report",
            {
                "invoices": str(inv_csv),
                "expenses": str(exp_csv),
                "out": "report.json",
                "apply": True,
            },
        )
        assert overwrite_res.is_error is True
        assert json_path.read_bytes() == original_bytes

        traversal_res = await rw_client.call_tool(
            "export_report",
            {
                "invoices": str(inv_csv),
                "expenses": str(exp_csv),
                "out": "../escape.json",
                "apply": True,
            },
        )
        assert traversal_res.is_error is True
        assert not (tmp_path / "escape.json").exists()

        symlink_res = await rw_client.call_tool(
            "export_report",
            {
                "invoices": str(inv_csv),
                "expenses": str(exp_csv),
                "out": "link_out/escape.json",
                "apply": True,
            },
        )
        assert symlink_res.is_error is True
        assert not (outside_dir / "escape.json").exists()

        suffix_res = await rw_client.call_tool(
            "export_report",
            {
                "invoices": str(inv_csv),
                "expenses": str(exp_csv),
                "out": "report.txt",
                "apply": True,
            },
        )
        assert suffix_res.is_error is True
        assert not (write_root / "report.txt").exists()

        csv_res = await rw_client.call_tool(
            "export_report",
            {
                "invoices": str(inv_csv),
                "expenses": str(exp_csv),
                "out": "nested/report.csv",
                "apply": True,
            },
        )
        assert csv_res.is_error is False
        csv_export = ExportResult.model_validate(csv_res.structured_content)
        assert csv_export.written is True
        csv_path = Path(csv_export.path)
        assert csv_path.is_file()
        assert hashlib.sha256(csv_path.read_bytes()).hexdigest() == csv_export.sha256

    all_events = _read_audit_events(audit_log)
    assert [ev.outcome for ev in all_events] == [
        "ok",
        "denied",
        "ok",
        "denied",
        "denied",
        "denied",
        "denied",
        "ok",
    ]


@pytest.mark.anyio
async def test_server_read_root_denial_and_audit_tail(
    tmp_path: Path,
    fixtures_dir: Path,
) -> None:
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    audit_log = tmp_path / "audit.jsonl"
    policy = Policy(
        allow_write=False,
        write_root=tmp_path / "out",
        read_root=allowed_dir,
        audit_log=audit_log,
    )

    async with Client(build_server(policy)) as client:
        denied_res = await client.call_tool(
            "inspect_source",
            {"path": str(fixtures_dir / "invoices.csv")},
        )
        assert denied_res.is_error is True

        tail_res = await client.call_tool("audit_tail", {"n": 10})
        assert tail_res.is_error is False
        assert tail_res.structured_content is not None
        tail_events = [
            AuditEvent.model_validate(item) for item in tail_res.structured_content["result"]
        ]
        assert len(tail_events) == 1
        assert tail_events[0].actor == "mcp"
        assert tail_events[0].tool == "inspect_source"
        assert tail_events[0].outcome == "denied"

        zero_res = await client.call_tool("audit_tail", {"n": 0})
        assert zero_res.is_error is True

        over_res = await client.call_tool("audit_tail", {"n": 201})
        assert over_res.is_error is True

    all_events = _read_audit_events(audit_log)
    assert [ev.outcome for ev in all_events] == ["denied", "ok", "error", "error"]


@pytest.mark.anyio
async def test_server_stdio_subprocess_smoke_no_stdout_pollution(
    tmp_path: Path,
    fixtures_dir: Path,
) -> None:
    src_root = Path(__file__).resolve().parents[1] / "src"
    audit_path = tmp_path / "stdio_audit.jsonl"
    write_root = tmp_path / "out"

    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        f"{src_root}{os.pathsep}{existing_pythonpath}" if existing_pythonpath else str(src_root)
    )
    env["RECON_AUDIT_LOG"] = str(audit_path)
    env["RECON_WRITE_ROOT"] = str(write_root)
    env.pop("RECON_ALLOW_WRITE", None)

    received_exceptions: list[Exception] = []

    async def _on_message(message: object) -> None:
        if isinstance(message, Exception):
            received_exceptions.append(message)

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "recon_mcp.server"],
        env=env,
        cwd=tmp_path,
    )

    async with Client(params, raise_exceptions=True, message_handler=_on_message) as client:
        listed = await client.list_tools()
        assert {tool.name for tool in listed.tools} == {
            "inspect_source",
            "reconcile",
            "export_report",
            "audit_tail",
        }

        info_res = await client.call_tool(
            "inspect_source",
            {"path": str(fixtures_dir / "invoices.csv")},
        )
        assert info_res.is_error is False
        assert info_res.structured_content is not None
        assert info_res.structured_content["rows"] == 5

        denied_res = await client.call_tool(
            "export_report",
            {
                "invoices": str(fixtures_dir / "invoices.csv"),
                "expenses": str(fixtures_dir / "expenses.csv"),
                "out": "denied.json",
                "apply": True,
            },
        )
        assert denied_res.is_error is True
        assert not (write_root / "denied.json").exists()

    assert received_exceptions == []

    events = _read_audit_events(audit_path)
    assert len(events) == 2
    assert [ev.actor for ev in events] == ["mcp", "mcp"]
    assert [ev.outcome for ev in events] == ["ok", "denied"]

    audit_text = audit_path.read_text(encoding="utf-8")
    assert "1250.00" not in audit_text
    assert "Acme Corp" not in audit_text
