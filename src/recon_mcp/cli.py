"""Command-line interface for recon-mcp (`recon reconcile|export|serve`)."""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib
import io
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Literal, NoReturn

from recon_mcp.audit import AuditLog, sha256_file
from recon_mcp.guards import GuardError, Policy, resolve_read, resolve_write, write_guarded
from recon_mcp.loaders import LoaderError, load_records
from recon_mcp.models import ExportResult, ReconReport
from recon_mcp.reconcile import reconcile

EXIT_OK = 0
EXIT_UNMATCHED = 1
EXIT_USAGE_OR_INPUT = 2
EXIT_DENIED = 3

_SUBCOMMANDS: frozenset[str] = frozenset({"reconcile", "export", "serve"})
_CSV_HEADER: tuple[str, ...] = (
    "status",
    "invoice_id",
    "expense_id",
    "reason",
    "amount_delta",
    "date_delta_days",
    "currency",
    "date",
    "counterparty",
    "amount",
    "reference",
)


class _UsageError(Exception):
    """Raised instead of SystemExit when argparse encounters a usage error."""


class _ReconArgumentParser(argparse.ArgumentParser):
    """ArgumentParser subclass that raises _UsageError instead of calling sys.exit."""

    def error(self, message: str) -> NoReturn:
        raise _UsageError(message)


def _extract_audit_log_from_argv(argv: Sequence[str]) -> str | None:
    """Scan raw argv for --audit-log so parse failures still audit to the intended path."""
    for idx, arg in enumerate(argv):
        if arg == "--":
            break
        if arg == "--audit-log" and idx + 1 < len(argv):
            return argv[idx + 1]
        if arg.startswith("--audit-log="):
            return arg.split("=", 1)[1]
    return None


def _extract_subcommand_from_argv(argv: Sequence[str]) -> str:
    """Return the first subcommand arg in argv, or 'cli' if none was supplied."""
    for arg in argv:
        if arg == "--":
            break
        if arg in _SUBCOMMANDS:
            return arg
    return "cli"


def _build_parser() -> _ReconArgumentParser:
    parser = _ReconArgumentParser(
        prog="recon",
        description="Offline invoice & expense reconciliation CLI and MCP stdio server.",
    )
    parser.add_argument(
        "--audit-log",
        default=None,
        help="Path to the JSONL audit log (default: ./.recon/audit.jsonl or RECON_AUDIT_LOG).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    reconcile_parser = subparsers.add_parser(
        "reconcile",
        help="Reconcile invoices against expenses (read-only).",
    )
    reconcile_parser.add_argument("--invoices", required=True, help="Invoices CSV/SQLite path.")
    reconcile_parser.add_argument("--expenses", required=True, help="Expenses CSV/SQLite path.")
    reconcile_parser.add_argument("--table-invoices", default=None, help="SQLite invoices table.")
    reconcile_parser.add_argument("--table-expenses", default=None, help="SQLite expenses table.")
    reconcile_parser.add_argument("--tolerance", default="0.00", help="Amount tolerance (Decimal).")
    reconcile_parser.add_argument("--window-days", type=int, default=3, help="Date window in days.")
    reconcile_parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Print ReconReport JSON to stdout.",
    )
    reconcile_parser.add_argument(
        "--audit-log",
        default=argparse.SUPPRESS,
        help="Path to the JSONL audit log.",
    )

    export_parser = subparsers.add_parser(
        "export",
        help="Reconcile and export report inside write_root (dry run by default).",
    )
    export_parser.add_argument("--invoices", required=True, help="Invoices CSV/SQLite path.")
    export_parser.add_argument("--expenses", required=True, help="Expenses CSV/SQLite path.")
    export_parser.add_argument("--out", required=True, help="Output .csv or .json path.")
    export_parser.add_argument("--table-invoices", default=None, help="SQLite invoices table.")
    export_parser.add_argument("--table-expenses", default=None, help="SQLite expenses table.")
    export_parser.add_argument("--tolerance", default="0.00", help="Amount tolerance (Decimal).")
    export_parser.add_argument("--window-days", type=int, default=3, help="Date window in days.")
    export_parser.add_argument(
        "--allow-write",
        action="store_true",
        default=None,
        help="Allow guarded writes when paired with --apply.",
    )
    export_parser.add_argument(
        "--apply",
        action="store_true",
        help="Write the exported file instead of performing a dry run.",
    )
    export_parser.add_argument(
        "--write-root",
        default=None,
        help="Containment directory for output files (default: ./out or RECON_WRITE_ROOT).",
    )
    export_parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Print ExportResult JSON to stdout.",
    )
    export_parser.add_argument(
        "--audit-log",
        default=argparse.SUPPRESS,
        help="Path to the JSONL audit log.",
    )

    serve_parser = subparsers.add_parser(
        "serve",
        help="Run the recon-mcp server over stdio.",
    )
    serve_parser.add_argument(
        "--allow-write",
        action="store_true",
        default=None,
        help="Allow export_report tool to write files when apply=True.",
    )
    serve_parser.add_argument(
        "--write-root",
        default=None,
        help="Containment directory for exported files (default: ./out or RECON_WRITE_ROOT).",
    )
    serve_parser.add_argument(
        "--audit-log",
        default=argparse.SUPPRESS,
        help="Path to the JSONL audit log.",
    )

    return parser


def serialize_report(report: ReconReport, suffix: str) -> tuple[str, int]:
    """Serialize a ReconReport as formatted JSON or CSV along with total row count."""
    row_count = (
        len(report.matched) + len(report.unmatched_invoices) + len(report.unmatched_expenses)
    )
    normalized = suffix.lower()
    if normalized == ".json":
        return f"{report.model_dump_json(indent=2)}\n", row_count
    if normalized == ".csv":
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(_CSV_HEADER)
        for match in report.matched:
            writer.writerow(
                [
                    "matched",
                    match.invoice_id,
                    match.expense_id,
                    match.reason,
                    f"{match.amount_delta:.2f}",
                    str(match.date_delta_days),
                    match.currency,
                    "",
                    "",
                    "",
                    "",
                ]
            )
        for inv in report.unmatched_invoices:
            writer.writerow(
                [
                    "unmatched_invoice",
                    inv.id,
                    "",
                    "",
                    "",
                    "",
                    inv.currency,
                    inv.date.isoformat(),
                    inv.counterparty,
                    f"{inv.amount:.2f}",
                    inv.reference,
                ]
            )
        for exp in report.unmatched_expenses:
            writer.writerow(
                [
                    "unmatched_expense",
                    "",
                    exp.id,
                    "",
                    "",
                    "",
                    exp.currency,
                    exp.date.isoformat(),
                    exp.counterparty,
                    f"{exp.amount:.2f}",
                    exp.reference,
                ]
            )
        return buf.getvalue(), row_count
    raise GuardError(f"Unsupported write suffix {suffix!r}; allowed: .csv, .json")


def _resolve_and_hash_inputs(
    invoices_arg: str,
    expenses_arg: str,
    policy: Policy,
    inputs_sha256: dict[str, str],
) -> tuple[Path, Path]:
    inv_path = resolve_read(invoices_arg, policy)
    inputs_sha256[str(inv_path)] = sha256_file(inv_path)
    exp_path = resolve_read(expenses_arg, policy)
    inputs_sha256[str(exp_path)] = sha256_file(exp_path)
    return inv_path, exp_path


def _cmd_reconcile(ns: argparse.Namespace, policy: Policy, audit: AuditLog) -> int:
    audit_args: dict[str, object] = {
        "invoices": ns.invoices,
        "expenses": ns.expenses,
        "table_invoices": ns.table_invoices,
        "table_expenses": ns.table_expenses,
        "window_days": ns.window_days,
    }
    inputs_sha256: dict[str, str] = {}
    try:
        inv_path, exp_path = _resolve_and_hash_inputs(
            ns.invoices, ns.expenses, policy, inputs_sha256
        )
        invoices = load_records(inv_path, table=ns.table_invoices)
        expenses = load_records(exp_path, table=ns.table_expenses)
        report = reconcile(
            invoices,
            expenses,
            tolerance=ns.tolerance,
            window_days=ns.window_days,
        )
    except GuardError as exc:
        audit.record(
            actor="cli",
            tool="reconcile",
            mode="read",
            dry_run=False,
            outcome="denied",
            args=audit_args,
            inputs_sha256=inputs_sha256,
            error=str(exc),
        )
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_DENIED
    except (LoaderError, ValueError) as exc:
        audit.record(
            actor="cli",
            tool="reconcile",
            mode="read",
            dry_run=False,
            outcome="error",
            args=audit_args,
            inputs_sha256=inputs_sha256,
            error=str(exc),
        )
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE_OR_INPUT

    report_json = report.model_dump_json()
    result_sha256 = hashlib.sha256(report_json.encode("utf-8")).hexdigest()
    audit.record(
        actor="cli",
        tool="reconcile",
        mode="read",
        dry_run=False,
        outcome="ok",
        args=audit_args,
        inputs_sha256=inputs_sha256,
        result_sha256=result_sha256,
    )

    if ns.as_json:
        print(report_json)
    else:
        print(
            f"matched={len(report.matched)} "
            f"unmatched_invoices={len(report.unmatched_invoices)} "
            f"unmatched_expenses={len(report.unmatched_expenses)}"
        )
        print(
            f"totals: invoices={report.totals.invoices} "
            f"expenses={report.totals.expenses} "
            f"delta={report.totals.delta}"
        )

    if report.unmatched_invoices or report.unmatched_expenses:
        return EXIT_UNMATCHED
    return EXIT_OK


def _cmd_export(ns: argparse.Namespace, policy: Policy, audit: AuditLog) -> int:
    apply = bool(ns.apply)
    dry_run = not apply
    audit_args: dict[str, object] = {
        "invoices": ns.invoices,
        "expenses": ns.expenses,
        "out": ns.out,
        "table_invoices": ns.table_invoices,
        "table_expenses": ns.table_expenses,
        "window_days": ns.window_days,
        "apply": apply,
        "allow_write": policy.allow_write,
    }
    inputs_sha256: dict[str, str] = {}
    try:
        inv_path, exp_path = _resolve_and_hash_inputs(
            ns.invoices, ns.expenses, policy, inputs_sha256
        )
        target = resolve_write(ns.out, policy, apply=apply)
        invoices = load_records(inv_path, table=ns.table_invoices)
        expenses = load_records(exp_path, table=ns.table_expenses)
        report = reconcile(
            invoices,
            expenses,
            tolerance=ns.tolerance,
            window_days=ns.window_days,
        )
        payload, row_count = serialize_report(report, target.suffix)
        write_result = write_guarded(ns.out, payload, policy, apply=apply)
    except GuardError as exc:
        audit.record(
            actor="cli",
            tool="export",
            mode="write",
            dry_run=dry_run,
            outcome="denied",
            args=audit_args,
            inputs_sha256=inputs_sha256,
            error=str(exc),
        )
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_DENIED
    except (LoaderError, ValueError, OSError) as exc:
        audit.record(
            actor="cli",
            tool="export",
            mode="write",
            dry_run=dry_run,
            outcome="error",
            args=audit_args,
            inputs_sha256=inputs_sha256,
            error=str(exc),
        )
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE_OR_INPUT

    export_result = ExportResult(
        written=write_result.written,
        path=str(write_result.path),
        rows=row_count,
        sha256=write_result.sha256,
    )
    audit.record(
        actor="cli",
        tool="export",
        mode="write",
        dry_run=dry_run,
        outcome="ok",
        args=audit_args,
        inputs_sha256=inputs_sha256,
        result_sha256=export_result.sha256,
    )

    if ns.as_json:
        print(export_result.model_dump_json())
    else:
        status = "written" if export_result.written else "dry-run"
        print(
            f"{status}: rows={export_result.rows} "
            f"path={export_result.path} sha256={export_result.sha256}"
        )
    return EXIT_OK


def _cmd_serve(policy: Policy, audit: AuditLog) -> int:
    # Enforce stdio hygiene: never write anything to stdout in serve mode.
    mode: Literal["read", "write"] = "write" if policy.allow_write else "read"
    audit_args: dict[str, object] = {"allow_write": policy.allow_write}
    try:
        server_mod = importlib.import_module("recon_mcp.server")
        build_server = server_mod.build_server
        server = build_server(policy)
    except GuardError as exc:
        audit.record(
            actor="cli",
            tool="serve",
            mode=mode,
            dry_run=False,
            outcome="denied",
            args=audit_args,
            error=str(exc),
        )
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_DENIED
    except Exception as exc:  # noqa: BLE001
        audit.record(
            actor="cli",
            tool="serve",
            mode=mode,
            dry_run=False,
            outcome="error",
            args=audit_args,
            error=str(exc),
        )
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE_OR_INPUT

    audit.record(
        actor="cli",
        tool="serve",
        mode=mode,
        dry_run=False,
        outcome="ok",
        args=audit_args,
    )
    try:
        server.run("stdio")
    except Exception as exc:  # noqa: BLE001
        audit.record(
            actor="cli",
            tool="serve",
            mode=mode,
            dry_run=False,
            outcome="error",
            args=audit_args,
            error=str(exc),
        )
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE_OR_INPUT
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the `recon` CLI returning POSIX exit codes 0/1/2/3."""
    args_list = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()
    try:
        ns = parser.parse_args(args_list)
    except _UsageError as exc:
        audit_path = Policy.from_env(
            audit_log=_extract_audit_log_from_argv(args_list),
        ).audit_log
        AuditLog(audit_path).record(
            actor="cli",
            tool=_extract_subcommand_from_argv(args_list),
            mode="read",
            dry_run=False,
            outcome="error",
            error=str(exc),
        )
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE_OR_INPUT
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else EXIT_USAGE_OR_INPUT
        audit_path = Policy.from_env(
            audit_log=_extract_audit_log_from_argv(args_list),
        ).audit_log
        AuditLog(audit_path).record(
            actor="cli",
            tool="help" if code == 0 else _extract_subcommand_from_argv(args_list),
            mode="read",
            dry_run=False,
            outcome="ok" if code == 0 else "error",
        )
        return code

    policy = Policy.from_env(
        allow_write=True if getattr(ns, "allow_write", None) else None,
        write_root=getattr(ns, "write_root", None),
        audit_log=getattr(ns, "audit_log", None),
    )
    audit = AuditLog(policy.audit_log)

    if ns.command == "reconcile":
        return _cmd_reconcile(ns, policy, audit)
    if ns.command == "export":
        return _cmd_export(ns, policy, audit)
    if ns.command == "serve":
        return _cmd_serve(policy, audit)

    audit.record(
        actor="cli",
        tool="cli",
        mode="read",
        dry_run=False,
        outcome="error",
        error=f"Unknown command: {ns.command}",
    )
    return EXIT_USAGE_OR_INPUT


if __name__ == "__main__":
    raise SystemExit(main())
