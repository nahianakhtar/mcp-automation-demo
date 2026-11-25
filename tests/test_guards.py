"""Unit tests for read/write path policy and safety guardrails."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from recon_mcp.guards import (
    MAX_READ_BYTES,
    GuardError,
    Policy,
    resolve_read,
    resolve_write,
    write_guarded,
)


def test_policy_defaults_and_from_env(tmp_path: Path) -> None:
    default_policy = Policy()
    assert default_policy.allow_write is False
    assert default_policy.write_root == Path("out")
    assert default_policy.read_root is None
    assert default_policy.audit_log == Path(".recon/audit.jsonl")
    assert default_policy.max_read_bytes == MAX_READ_BYTES

    env_policy = Policy.from_env(
        env={
            "RECON_ALLOW_WRITE": "1",
            "RECON_WRITE_ROOT": str(tmp_path / "exports"),
            "RECON_READ_ROOT": str(tmp_path / "inputs"),
            "RECON_AUDIT_LOG": str(tmp_path / "audit.jsonl"),
        }
    )
    assert env_policy.allow_write is True
    assert env_policy.write_root == tmp_path / "exports"
    assert env_policy.read_root == tmp_path / "inputs"
    assert env_policy.audit_log == tmp_path / "audit.jsonl"

    non_one_policy = Policy.from_env(env={"RECON_ALLOW_WRITE": "true"})
    assert non_one_policy.allow_write is False


def test_resolve_read_valid_and_errors(tmp_path: Path, tmp_policy: Policy) -> None:
    data_file = tmp_path / "invoices.csv"
    data_file.write_text("id\n1\n", encoding="utf-8")

    assert resolve_read(data_file, tmp_policy) == data_file.resolve()

    with pytest.raises(GuardError, match="not found"):
        resolve_read(tmp_path / "missing.csv", tmp_policy)

    with pytest.raises(GuardError, match="regular file"):
        resolve_read(tmp_path, tmp_policy)

    with pytest.raises(GuardError, match="null byte"):
        resolve_read("invoices\x00.csv", tmp_policy)

    capped_policy = Policy(max_read_bytes=4)
    with pytest.raises(GuardError, match="byte limit"):
        resolve_read(data_file, capped_policy)


def test_resolve_read_enforces_read_root_and_denies_escapes(tmp_path: Path) -> None:
    read_root = tmp_path / "inputs"
    read_root.mkdir()
    inside = read_root / "in.csv"
    inside.write_text("a\n1\n", encoding="utf-8")

    outside = tmp_path / "secret.csv"
    outside.write_text("a\n2\n", encoding="utf-8")

    symlink_escape = read_root / "escape.csv"
    symlink_escape.symlink_to(outside)

    policy = Policy(read_root=read_root)
    assert resolve_read(inside, policy) == inside.resolve()

    with pytest.raises(GuardError, match="escapes read_root"):
        resolve_read(read_root / ".." / "secret.csv", policy)

    with pytest.raises(GuardError, match="escapes read_root"):
        resolve_read(symlink_escape, policy)


def test_dry_run_by_default_creates_no_files(tmp_path: Path, tmp_policy: Policy) -> None:
    result = write_guarded("report.json", '{"ok": true}', tmp_policy)

    assert result.written is False
    assert result.path == (tmp_path / "out" / "report.json").resolve()
    assert result.sha256 == hashlib.sha256(b'{"ok": true}').hexdigest()
    assert not (tmp_path / "out").exists()
    assert not result.path.exists()


def test_apply_without_allow_write_raises_guard_error(tmp_policy: Policy) -> None:
    with pytest.raises(GuardError, match="does not allow writes"):
        write_guarded("report.json", "{}", tmp_policy, apply=True)


def test_write_guarded_atomic_json_and_csv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy = Policy(allow_write=True, write_root=tmp_path / "out")

    replace_calls: list[tuple[Path, Path]] = []
    real_replace = os.replace

    def spy_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        src_path = Path(src)
        dst_path = Path(dst)
        replace_calls.append((src_path, dst_path))
        assert src_path.parent == dst_path.parent
        assert src_path.exists()
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", spy_replace)

    json_res = write_guarded("nested/report.json", '{"rows": 1}\n', policy, apply=True)
    csv_res = write_guarded("report.csv", "a,b\n1,2\n", policy, apply=True)

    assert json_res.written is True
    assert json_res.path.read_text(encoding="utf-8") == '{"rows": 1}\n'
    assert json_res.sha256 == hashlib.sha256(b'{"rows": 1}\n').hexdigest()

    assert csv_res.written is True
    assert csv_res.path.read_text(encoding="utf-8") == "a,b\n1,2\n"
    assert len(replace_calls) == 2

    leftover_tmps = list((tmp_path / "out").rglob("*.tmp"))
    assert leftover_tmps == []


def test_write_guarded_cleans_temp_file_on_replace_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = Policy(allow_write=True, write_root=tmp_path / "out")

    def fail_replace(_src: str | os.PathLike[str], _dst: str | os.PathLike[str]) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr(os, "replace", fail_replace)

    with pytest.raises(OSError, match="simulated replace failure"):
        write_guarded("report.json", "{}", policy, apply=True)

    assert not (tmp_path / "out" / "report.json").exists()
    assert list((tmp_path / "out").glob("*.tmp")) == []


def test_resolve_write_denies_traversal_and_outside_paths(tmp_path: Path) -> None:
    policy = Policy(allow_write=True, write_root=tmp_path / "out")
    outside_abs = tmp_path / "outside.json"

    for bad_path in (
        "../outside.json",
        "sub/../../outside.csv",
        str(outside_abs),
        ".",
        "",
        "bad\x00.json",
    ):
        with pytest.raises(GuardError):
            resolve_write(bad_path, policy, apply=True)


def test_resolve_write_denies_symlinks(tmp_path: Path) -> None:
    write_root = tmp_path / "out"
    write_root.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    inside_dir = write_root / "real"
    inside_dir.mkdir()

    symlink_dir_out = write_root / "link_out"
    symlink_dir_out.symlink_to(outside_dir)

    symlink_dir_in = write_root / "link_in"
    symlink_dir_in.symlink_to(inside_dir)

    dangling_link = write_root / "dangling.json"
    dangling_link.symlink_to(outside_dir / "target.json")

    policy = Policy(allow_write=True, write_root=write_root)

    with pytest.raises(GuardError):
        resolve_write("link_out/report.json", policy, apply=True)

    with pytest.raises(GuardError, match="Symlink"):
        resolve_write("link_in/report.json", policy, apply=True)

    with pytest.raises(GuardError):
        resolve_write("dangling.json", policy, apply=True)

    symlink_root = tmp_path / "sym_root"
    symlink_root.symlink_to(write_root)
    with pytest.raises(GuardError, match="Write root must not be a symlink"):
        resolve_write("ok.json", Policy(allow_write=True, write_root=symlink_root), apply=True)


def test_resolve_write_denies_unsupported_suffix_and_overwrite(tmp_path: Path) -> None:
    write_root = tmp_path / "out"
    write_root.mkdir()
    existing = write_root / "existing.json"
    existing.write_text('{"keep": true}', encoding="utf-8")

    policy = Policy(allow_write=True, write_root=write_root)

    with pytest.raises(GuardError, match="Unsupported write suffix"):
        resolve_write("report.txt", policy, apply=True)

    with pytest.raises(GuardError, match="Unsupported write suffix"):
        resolve_write("report", policy, apply=True)

    with pytest.raises(GuardError, match="overwrite"):
        write_guarded("existing.json", '{"overwrite": true}', policy, apply=True)

    assert existing.read_text(encoding="utf-8") == '{"keep": true}'
