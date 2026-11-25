"""Read/write path policy and safety guardrails for recon-mcp."""

from __future__ import annotations

import contextlib
import hashlib
import os
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

MAX_READ_BYTES = 50 * 1024 * 1024
ALLOWED_WRITE_SUFFIXES: frozenset[str] = frozenset({".csv", ".json"})


class GuardError(Exception):
    """Raised when a read/write guardrail policy check rejects an operation."""


@dataclass(frozen=True, slots=True)
class Policy:
    """Runtime safety policy governing read containment, writes, and audit logging."""

    allow_write: bool = False
    write_root: Path = field(default_factory=lambda: Path("out"))
    read_root: Path | None = None
    audit_log: Path = field(default_factory=lambda: Path(".recon/audit.jsonl"))
    max_read_bytes: int = MAX_READ_BYTES

    @classmethod
    def from_env(
        cls,
        *,
        allow_write: bool | None = None,
        write_root: Path | str | None = None,
        read_root: Path | str | None = None,
        audit_log: Path | str | None = None,
        env: Mapping[str, str] | None = None,
    ) -> Policy:
        """Build a Policy from explicit overrides and environment variables."""
        source = os.environ if env is None else env
        resolved_allow_write = (
            source.get("RECON_ALLOW_WRITE") == "1" if allow_write is None else bool(allow_write)
        )
        resolved_write_root = (
            Path(write_root)
            if write_root is not None
            else Path(source.get("RECON_WRITE_ROOT") or "out")
        )
        env_read_root = source.get("RECON_READ_ROOT")
        resolved_read_root = (
            Path(read_root)
            if read_root is not None
            else (Path(env_read_root) if env_read_root else None)
        )
        resolved_audit_log = (
            Path(audit_log)
            if audit_log is not None
            else Path(source.get("RECON_AUDIT_LOG") or ".recon/audit.jsonl")
        )
        return cls(
            allow_write=resolved_allow_write,
            write_root=resolved_write_root,
            read_root=resolved_read_root,
            audit_log=resolved_audit_log,
        )


@dataclass(frozen=True, slots=True)
class WriteResult:
    """Outcome of a guarded write or dry run."""

    written: bool
    path: Path
    sha256: str


def _reject_null_bytes(path: Path | str) -> str:
    raw = os.fspath(path)
    text = raw.decode("utf-8", errors="surrogateescape") if isinstance(raw, bytes) else raw
    if "\x00" in text:
        raise GuardError("Path contains null byte")
    return text


def _ensure_no_symlinks_under(base: Path, target: Path) -> None:
    """Reject any symlink component between base and target (inclusive of target)."""
    try:
        rel = target.relative_to(base)
    except ValueError:
        return
    current = base
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            raise GuardError(f"Symlink component not allowed in write path: {current}")


def resolve_read(path: Path | str, policy: Policy) -> Path:
    """Validate and resolve a readable regular file path against policy."""
    _reject_null_bytes(path)
    try:
        resolved = Path(path).resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise GuardError(f"Readable file not found: {path}") from exc

    try:
        st = resolved.stat()
    except OSError as exc:
        raise GuardError(f"Unable to stat input file: {path}") from exc

    if not stat.S_ISREG(st.st_mode):
        raise GuardError(f"Input path is not a regular file: {path}")

    if st.st_size > policy.max_read_bytes:
        raise GuardError(f"Input file exceeds {policy.max_read_bytes} byte limit: {resolved}")

    if policy.read_root is not None:
        try:
            root = policy.read_root.resolve(strict=True)
        except (OSError, ValueError) as exc:
            raise GuardError(f"Configured read_root is invalid: {policy.read_root}") from exc
        if not root.is_dir():
            raise GuardError(f"Configured read_root is not a directory: {policy.read_root}")
        if not resolved.is_relative_to(root):
            raise GuardError(f"Read path escapes read_root: {path}")

    return resolved


def resolve_write(path: Path | str, policy: Policy, *, apply: bool = False) -> Path:
    """Validate and resolve an output path inside policy.write_root without overwriting."""
    text = _reject_null_bytes(path)
    if not text.strip():
        raise GuardError("Write path must not be empty")

    if apply and not policy.allow_write:
        raise GuardError("Write denied: policy does not allow writes")

    if policy.write_root.is_symlink():
        raise GuardError(f"Write root must not be a symlink: {policy.write_root}")

    try:
        root = policy.write_root.resolve(strict=False)
    except (OSError, ValueError) as exc:
        raise GuardError(f"Invalid write_root: {policy.write_root}") from exc

    candidate = Path(text)
    raw_target = candidate if candidate.is_absolute() else (root / candidate)

    _ensure_no_symlinks_under(policy.write_root, raw_target)
    _ensure_no_symlinks_under(root, raw_target)
    if raw_target.is_symlink():
        raise GuardError(f"Symlink target not allowed in write path: {raw_target}")

    try:
        resolved = raw_target.resolve(strict=False)
    except (OSError, ValueError) as exc:
        raise GuardError(f"Invalid write path: {path}") from exc

    if not resolved.is_relative_to(root):
        raise GuardError(f"Write path escapes write_root: {path}")

    if resolved == root:
        raise GuardError("Write path must name a file inside write_root")

    if resolved.suffix.lower() not in ALLOWED_WRITE_SUFFIXES:
        raise GuardError(f"Unsupported write suffix {resolved.suffix!r}; allowed: .csv, .json")

    if resolved.exists() or resolved.is_symlink() or raw_target.exists() or raw_target.is_symlink():
        raise GuardError(f"Refusing to overwrite existing path: {resolved}")

    return resolved


def write_guarded(
    path: Path | str,
    data: bytes | str,
    policy: Policy,
    *,
    apply: bool = False,
) -> WriteResult:
    """Perform a dry run or atomic guarded file write inside policy.write_root."""
    payload = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    digest = hashlib.sha256(payload).hexdigest()
    target = resolve_write(path, policy, apply=apply)

    if not apply:
        return WriteResult(written=False, path=target, sha256=digest)

    target.parent.mkdir(parents=True, exist_ok=True)

    root = policy.write_root.resolve(strict=True)
    parent_resolved = target.parent.resolve(strict=True)
    if not parent_resolved.is_relative_to(root):
        raise GuardError(f"Write parent escapes write_root: {target.parent}")
    if target.exists() or target.is_symlink():
        raise GuardError(f"Refusing to overwrite existing path: {target}")

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=target.parent,
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if target.exists() or target.is_symlink():
            raise GuardError(f"Refusing to overwrite existing path: {target}")
        os.replace(tmp_path, target)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise

    return WriteResult(written=True, path=target, sha256=digest)
