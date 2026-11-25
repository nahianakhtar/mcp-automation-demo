"""Tests for models, CSV/SQLite read-only loaders, and the offline socket guard."""

from __future__ import annotations

import contextlib
import socket
import sqlite3
from datetime import date
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

from recon_mcp.loaders import (
    LoaderError,
    inspect_source,
    load_csv,
    load_records,
    load_sqlite,
    open_sqlite_readonly,
)
from recon_mcp.models import Record


def test_load_csv_fixtures(fixtures_dir: Path) -> None:
    invoices = load_csv(fixtures_dir / "invoices.csv")
    expenses = load_csv(fixtures_dir / "expenses.csv")

    assert len(invoices) == 5
    assert len(expenses) == 5

    assert invoices[0] == Record(
        id="INV-001",
        date=date(2026, 1, 10),
        counterparty="Acme Corp",
        amount=Decimal("1250.00"),
        currency="USD",
        reference="REF-1001",
    )
    assert invoices[1].reference == ""
    assert invoices[2].currency == "EUR"
    assert invoices[3].amount == Decimal("-50.00")


def test_load_sqlite_matches_csv_fixtures(fixtures_dir: Path, ledger_db: Path) -> None:
    csv_invoices = load_csv(fixtures_dir / "invoices.csv")
    csv_expenses = load_csv(fixtures_dir / "expenses.csv")

    db_invoices = load_sqlite(ledger_db, "invoices")
    db_expenses = load_sqlite(ledger_db, "expenses")

    assert db_invoices == csv_invoices
    assert db_expenses == csv_expenses


def test_load_records_dispatch_and_errors(
    fixtures_dir: Path, ledger_db: Path, tmp_path: Path
) -> None:
    assert load_records(fixtures_dir / "invoices.csv") == load_csv(fixtures_dir / "invoices.csv")
    assert load_records(ledger_db, table="expenses") == load_sqlite(ledger_db, "expenses")

    with pytest.raises(LoaderError, match="table name"):
        load_records(ledger_db)

    bad_file = tmp_path / "data.txt"
    bad_file.write_text("hello", encoding="utf-8")
    with pytest.raises(LoaderError, match="Unsupported input file type"):
        load_records(bad_file)


def test_inspect_source_csv_and_sqlite(fixtures_dir: Path, ledger_db: Path) -> None:
    csv_info = inspect_source(fixtures_dir / "invoices.csv")
    assert csv_info.kind == "csv"
    assert csv_info.rows == 5
    assert csv_info.columns == ["id", "date", "counterparty", "amount", "currency", "reference"]

    db_info = inspect_source(ledger_db, table="expenses")
    assert db_info.kind == "sqlite"
    assert db_info.rows == 5
    assert db_info.columns == ["id", "date", "counterparty", "amount", "currency", "reference"]


@pytest.mark.parametrize(
    ("raw_amount", "expected"),
    [
        ("0.005", Decimal("0.00")),
        ("0.015", Decimal("0.02")),
        ("-12.345", Decimal("-12.34")),
        ("-12.355", Decimal("-12.36")),
        ("-50", Decimal("-50.00")),
        (Decimal("10.1"), Decimal("10.10")),
    ],
)
def test_record_decimal_round_half_even(raw_amount: object, expected: Decimal) -> None:
    rec = Record(
        id="R-1",
        date="2026-01-01",
        counterparty="Test Co",
        amount=raw_amount,
        currency="usd",
        reference="",
    )
    assert rec.amount == expected
    assert rec.currency == "USD"


@pytest.mark.parametrize("bad_amount", [12.34, True, False, "", "NaN", "Infinity", "abc"])
def test_record_rejects_float_bool_and_invalid_amounts(bad_amount: object) -> None:
    with pytest.raises(ValidationError):
        Record(
            id="R-1",
            date="2026-01-01",
            counterparty="Test Co",
            amount=bad_amount,
            currency="USD",
            reference="",
        )


@pytest.mark.parametrize(
    "bad_table",
    [
        "invoices; DROP TABLE invoices--",
        'invoices" UNION SELECT 1,2,3,4,5,6--',
        "invoices WHERE 1=1",
        "sqlite_master",
        "",
        "123bad",
        "a" * 65,
        "nonexistent",
    ],
)
def test_sqlite_identifier_injection_rejected(ledger_db: Path, bad_table: str) -> None:
    with pytest.raises(LoaderError):
        load_sqlite(ledger_db, bad_table)

    with pytest.raises(LoaderError):
        inspect_source(ledger_db, table=bad_table)

    # Confirm the valid table was never dropped or modified.
    assert len(load_sqlite(ledger_db, "invoices")) == 5


def test_sqlite_mode_ro_rejects_writes(ledger_db: Path) -> None:
    with contextlib.closing(open_sqlite_readonly(ledger_db)) as conn:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute(
                "INSERT INTO invoices (id, date, counterparty, amount, currency, reference) "
                "VALUES ('INV-999', '2026-01-01', 'Evil', '1.00', 'USD', '')"
            )
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("CREATE TABLE hacked (x TEXT)")


def test_sqlite_rejects_real_float_amount(tmp_path: Path) -> None:
    db_path = tmp_path / "float.db"
    with contextlib.closing(sqlite3.connect(db_path)) as conn:
        conn.execute(
            "CREATE TABLE invoices ("
            "id TEXT, date TEXT, counterparty TEXT, amount REAL, currency TEXT, reference TEXT"
            ")"
        )
        conn.execute(
            "INSERT INTO invoices VALUES ('INV-1', '2026-01-01', 'Acme', 12.34, 'USD', 'R1')"
        )
        conn.commit()

    with pytest.raises(LoaderError, match="Invalid SQLite row"):
        load_sqlite(db_path, "invoices")


def test_csv_missing_columns_and_malformed_rows_rejected(tmp_path: Path) -> None:
    missing_col = tmp_path / "missing.csv"
    missing_col.write_text("id,date,counterparty,amount,currency\n1,2026-01-01,A,1.00,USD\n")
    with pytest.raises(LoaderError, match="Missing required columns"):
        load_csv(missing_col)

    short_row = tmp_path / "short.csv"
    short_row.write_text("id,date,counterparty,amount,currency,reference\n1,2026-01-01,A\n")
    with pytest.raises(LoaderError, match="Malformed CSV row"):
        load_csv(short_row)

    extra_col = tmp_path / "extra.csv"
    extra_col.write_text(
        "id,date,counterparty,amount,currency,reference\n1,2026-01-01,A,1.00,USD,R1,EXTRA\n"
    )
    with pytest.raises(LoaderError, match="Malformed CSV row"):
        load_csv(extra_col)


def test_network_guard_blocks_inet_and_allows_socketpair() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(RuntimeError, match="network disabled in tests"):
            sock.connect(("127.0.0.1", 80))
        with pytest.raises(RuntimeError, match="network disabled in tests"):
            sock.connect_ex(("127.0.0.1", 80))

    with pytest.raises(RuntimeError, match="network disabled in tests"):
        socket.create_connection(("127.0.0.1", 80))

    left, right = socket.socketpair()
    try:
        left.sendall(b"ping")
        assert right.recv(4) == b"ping"
    finally:
        left.close()
        right.close()
