"""Append-only JSONL audit logging with fsync and injectable clock."""

from __future__ import annotations

import hashlib
import os
from collections import deque
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from recon_mcp.models import AuditEvent

Clock = Callable[[], datetime]

ALLOWED_ARG_KEYS: frozenset[str] = frozenset(
    {
        "path",
        "invoices",
        "expenses",
        "out",
        "table",
        "table_invoices",
        "table_expenses",
        "window_days",
        "apply",
        "allow_write",
        "n",
    }
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def format_rfc3339_utc(dt: datetime) -> str:
    """Format a datetime as an RFC3339 UTC timestamp ending in 'Z'."""
    utc_dt = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    return utc_dt.isoformat().replace("+00:00", "Z")


def sha256_file(path: Path | str) -> str:
    """Compute hex SHA-256 digest of a file without loading it all into memory."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def sanitize_args(
    raw_args: Mapping[str, object] | None,
) -> dict[str, str | int | bool | None]:
    """Filter tool arguments to safe path/option metadata, never logging amounts or rows."""
    if not raw_args:
        return {}
    clean: dict[str, str | int | bool | None] = {}
    for key, value in raw_args.items():
        if key not in ALLOWED_ARG_KEYS:
            continue
        if isinstance(value, Path):
            clean[key] = str(value)
        elif value is None or isinstance(value, str | int | bool):
            clean[key] = value
    return clean


class AuditLog:
    """JSON Lines audit log with fsync durability and injectable UTC clock."""

    def __init__(
        self,
        path: Path | str = Path(".recon/audit.jsonl"),
        *,
        now: Clock | None = None,
    ) -> None:
        self.path = Path(path)
        self._now: Clock = _utc_now if now is None else now

    def make_event(
        self,
        *,
        actor: Literal["cli", "mcp"],
        tool: str,
        mode: Literal["read", "write"],
        dry_run: bool,
        outcome: Literal["ok", "denied", "error"],
        args: Mapping[str, object] | None = None,
        inputs_sha256: Mapping[str, str] | None = None,
        error: str | None = None,
        result_sha256: str | None = None,
    ) -> AuditEvent:
        """Construct a sanitized AuditEvent stamped with the injected clock."""
        return AuditEvent(
            ts=format_rfc3339_utc(self._now()),
            actor=actor,
            tool=tool,
            mode=mode,
            dry_run=dry_run,
            args=sanitize_args(args),
            inputs_sha256=dict(inputs_sha256) if inputs_sha256 else {},
            outcome=outcome,
            error=error,
            result_sha256=result_sha256,
        )

    def append(self, event: AuditEvent) -> AuditEvent:
        """Persist an AuditEvent as one JSONL line using flush + os.fsync."""
        sanitized = event.model_copy(update={"args": sanitize_args(event.args)})
        line = sanitized.model_dump_json() + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        return sanitized

    def record(
        self,
        *,
        actor: Literal["cli", "mcp"],
        tool: str,
        mode: Literal["read", "write"],
        dry_run: bool,
        outcome: Literal["ok", "denied", "error"],
        args: Mapping[str, object] | None = None,
        inputs_sha256: Mapping[str, str] | None = None,
        error: str | None = None,
        result_sha256: str | None = None,
    ) -> AuditEvent:
        """Build and append a sanitized AuditEvent in one call."""
        event = self.make_event(
            actor=actor,
            tool=tool,
            mode=mode,
            dry_run=dry_run,
            outcome=outcome,
            args=args,
            inputs_sha256=inputs_sha256,
            error=error,
            result_sha256=result_sha256,
        )
        return self.append(event)

    def tail(self, n: int = 20) -> list[AuditEvent]:
        """Return up to the last n AuditEvent records (1 <= n <= 200)."""
        if isinstance(n, bool) or not isinstance(n, int) or not (1 <= n <= 200):
            raise ValueError("n must be an integer between 1 and 200")
        if not self.path.exists():
            return []
        recent: deque[str] = deque(maxlen=n)
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped:
                    recent.append(stripped)
        return [AuditEvent.model_validate_json(line) for line in recent]
