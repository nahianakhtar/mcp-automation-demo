"""MCP stdio server exposing offline reconciliation tools and guardrails."""

from __future__ import annotations

import hashlib
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import TypeAdapter

from recon_mcp import __version__
from recon_mcp.audit import AuditLog, sha256_file
from recon_mcp.cli import serialize_report
from recon_mcp.guards import GuardError, Policy, resolve_read, resolve_write, write_guarded
from recon_mcp.loaders import LoaderError, load_records
from recon_mcp.loaders import inspect_source as load_source_info
from recon_mcp.models import AuditEvent, ExportResult, ReconReport, SourceInfo
from recon_mcp.reconcile import reconcile as reconcile_records

_AUDIT_EVENTS_ADAPTER = TypeAdapter(list[AuditEvent])


def _resolve_and_hash(
    path: str,
    policy: Policy,
    inputs_sha256: dict[str, str],
) -> Path:
    resolved = resolve_read(path, policy)
    inputs_sha256[str(resolved)] = sha256_file(resolved)
    return resolved


def build_server(
    policy: Policy | None = None,
    *,
    audit_log: AuditLog | None = None,
) -> MCPServer:
    """Create and configure the recon-mcp MCPServer instance."""
    active_policy = Policy.from_env() if policy is None else policy
    audit = AuditLog(active_policy.audit_log) if audit_log is None else audit_log

    server = MCPServer(
        "recon-mcp",
        instructions=(
            "Offline invoice and expense reconciliation server. "
            "Read-only by default; exporting files requires allow_write policy and apply=True."
        ),
        version=__version__,
    )

    @server.tool(
        annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False),
    )
    def inspect_source(path: str, table: str | None = None) -> SourceInfo:
        """Inspect a CSV or SQLite source read-only and return kind, row count, and columns."""
        audit_args: dict[str, object] = {"path": path, "table": table}
        inputs_sha256: dict[str, str] = {}
        try:
            resolved = _resolve_and_hash(path, active_policy, inputs_sha256)
            info = load_source_info(resolved, table=table)
        except GuardError as exc:
            audit.record(
                actor="mcp",
                tool="inspect_source",
                mode="read",
                dry_run=False,
                outcome="denied",
                args=audit_args,
                inputs_sha256=inputs_sha256,
                error=str(exc),
            )
            raise ToolError(str(exc)) from exc
        except (LoaderError, ValueError, OSError) as exc:
            audit.record(
                actor="mcp",
                tool="inspect_source",
                mode="read",
                dry_run=False,
                outcome="error",
                args=audit_args,
                inputs_sha256=inputs_sha256,
                error=str(exc),
            )
            raise ToolError(str(exc)) from exc

        result_sha256 = hashlib.sha256(info.model_dump_json().encode("utf-8")).hexdigest()
        audit.record(
            actor="mcp",
            tool="inspect_source",
            mode="read",
            dry_run=False,
            outcome="ok",
            args=audit_args,
            inputs_sha256=inputs_sha256,
            result_sha256=result_sha256,
        )
        return info

    @server.tool(
        annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False),
    )
    def reconcile(
        invoices: str,
        expenses: str,
        table_invoices: str | None = None,
        table_expenses: str | None = None,
        tolerance: str = "0.00",
        window_days: int = 3,
    ) -> ReconReport:
        """Reconcile invoices against expenses using deterministic Decimal matching."""
        audit_args: dict[str, object] = {
            "invoices": invoices,
            "expenses": expenses,
            "table_invoices": table_invoices,
            "table_expenses": table_expenses,
            "window_days": window_days,
        }
        inputs_sha256: dict[str, str] = {}
        try:
            inv_path = _resolve_and_hash(invoices, active_policy, inputs_sha256)
            exp_path = _resolve_and_hash(expenses, active_policy, inputs_sha256)
            inv_records = load_records(inv_path, table=table_invoices)
            exp_records = load_records(exp_path, table=table_expenses)
            report = reconcile_records(
                inv_records,
                exp_records,
                tolerance=tolerance,
                window_days=window_days,
            )
        except GuardError as exc:
            audit.record(
                actor="mcp",
                tool="reconcile",
                mode="read",
                dry_run=False,
                outcome="denied",
                args=audit_args,
                inputs_sha256=inputs_sha256,
                error=str(exc),
            )
            raise ToolError(str(exc)) from exc
        except (LoaderError, ValueError, OSError) as exc:
            audit.record(
                actor="mcp",
                tool="reconcile",
                mode="read",
                dry_run=False,
                outcome="error",
                args=audit_args,
                inputs_sha256=inputs_sha256,
                error=str(exc),
            )
            raise ToolError(str(exc)) from exc

        result_sha256 = hashlib.sha256(report.model_dump_json().encode("utf-8")).hexdigest()
        audit.record(
            actor="mcp",
            tool="reconcile",
            mode="read",
            dry_run=False,
            outcome="ok",
            args=audit_args,
            inputs_sha256=inputs_sha256,
            result_sha256=result_sha256,
        )
        return report

    @server.tool(
        annotations=ToolAnnotations(
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    def export_report(
        invoices: str,
        expenses: str,
        out: str,
        apply: bool = False,
    ) -> ExportResult:
        """Reconcile and export a .csv or .json report inside write_root (dry run by default)."""
        dry_run = not apply
        audit_args: dict[str, object] = {
            "invoices": invoices,
            "expenses": expenses,
            "out": out,
            "apply": apply,
            "allow_write": active_policy.allow_write,
        }
        inputs_sha256: dict[str, str] = {}
        try:
            inv_path = _resolve_and_hash(invoices, active_policy, inputs_sha256)
            exp_path = _resolve_and_hash(expenses, active_policy, inputs_sha256)
            target = resolve_write(out, active_policy, apply=apply)
            inv_records = load_records(inv_path)
            exp_records = load_records(exp_path)
            report = reconcile_records(inv_records, exp_records)
            payload, row_count = serialize_report(report, target.suffix)
            write_result = write_guarded(out, payload, active_policy, apply=apply)
        except GuardError as exc:
            audit.record(
                actor="mcp",
                tool="export_report",
                mode="write",
                dry_run=dry_run,
                outcome="denied",
                args=audit_args,
                inputs_sha256=inputs_sha256,
                error=str(exc),
            )
            raise ToolError(str(exc)) from exc
        except (LoaderError, ValueError, OSError) as exc:
            audit.record(
                actor="mcp",
                tool="export_report",
                mode="write",
                dry_run=dry_run,
                outcome="error",
                args=audit_args,
                inputs_sha256=inputs_sha256,
                error=str(exc),
            )
            raise ToolError(str(exc)) from exc

        result = ExportResult(
            written=write_result.written,
            path=str(write_result.path),
            rows=row_count,
            sha256=write_result.sha256,
        )
        audit.record(
            actor="mcp",
            tool="export_report",
            mode="write",
            dry_run=dry_run,
            outcome="ok",
            args=audit_args,
            inputs_sha256=inputs_sha256,
            result_sha256=result.sha256,
        )
        return result

    @server.tool(
        annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False),
    )
    def audit_tail(n: int = 20) -> list[AuditEvent]:
        """Return up to the last n sanitized audit log events (1 <= n <= 200)."""
        audit_args: dict[str, object] = {"n": n}
        try:
            events = audit.tail(n)
        except (ValueError, OSError) as exc:
            audit.record(
                actor="mcp",
                tool="audit_tail",
                mode="read",
                dry_run=False,
                outcome="error",
                args=audit_args,
                error=str(exc),
            )
            raise ToolError(str(exc)) from exc

        result_sha256 = hashlib.sha256(_AUDIT_EVENTS_ADAPTER.dump_json(events)).hexdigest()
        audit.record(
            actor="mcp",
            tool="audit_tail",
            mode="read",
            dry_run=False,
            outcome="ok",
            args=audit_args,
            result_sha256=result_sha256,
        )
        return events

    return server


def main() -> None:
    """Run the recon-mcp server over stdio."""
    policy = Policy.from_env()
    server = build_server(policy)
    server.run("stdio")


if __name__ == "__main__":
    main()
