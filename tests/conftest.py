"""Shared pytest fixtures and offline network guard."""

from __future__ import annotations

import contextlib
import socket
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from recon_mcp.guards import Policy

_ORIGINAL_CONNECT = socket.socket.connect
_ORIGINAL_CONNECT_EX = socket.socket.connect_ex


@pytest.fixture(autouse=True)
def _disable_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Block AF_INET/AF_INET6 socket connections while leaving AF_UNIX/socketpair intact."""

    def guarded_connect(self: socket.socket, address: Any) -> Any:
        if self.family in {socket.AF_INET, socket.AF_INET6}:
            raise RuntimeError("network disabled in tests")
        return _ORIGINAL_CONNECT(self, address)

    def guarded_connect_ex(self: socket.socket, address: Any) -> int:
        if self.family in {socket.AF_INET, socket.AF_INET6}:
            raise RuntimeError("network disabled in tests")
        return _ORIGINAL_CONNECT_EX(self, address)

    def guarded_create_connection(*_args: Any, **_kwargs: Any) -> socket.socket:
        raise RuntimeError("network disabled in tests")

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket, "create_connection", guarded_create_connection)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def ledger_db(tmp_path: Path, fixtures_dir: Path) -> Path:
    db_path = tmp_path / "ledger.sqlite"
    sql_script = (fixtures_dir / "ledger.sqlite.sql").read_text(encoding="utf-8")
    with contextlib.closing(sqlite3.connect(db_path)) as conn:
        conn.executescript(sql_script)
        conn.commit()
    return db_path


@pytest.fixture
def tmp_policy(tmp_path: Path) -> Policy:
    return Policy(
        allow_write=False,
        write_root=tmp_path / "out",
        read_root=None,
        audit_log=tmp_path / ".recon" / "audit.jsonl",
    )
