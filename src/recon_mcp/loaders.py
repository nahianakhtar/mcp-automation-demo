"""Read-only CSV and SQLite loaders with strict SQL identifier validation."""

from __future__ import annotations

import contextlib
import csv
import re
import sqlite3
from pathlib import Path

from pydantic import ValidationError

from recon_mcp.models import Record, SourceInfo

REQUIRED_COLUMNS: tuple[str, ...] = (
    "id",
    "date",
    "counterparty",
    "amount",
    "currency",
    "reference",
)
TABLE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
SQLITE_SUFFIXES: frozenset[str] = frozenset({".sqlite", ".db"})


class LoaderError(ValueError):
    """Raised when an input source cannot be validated or loaded safely."""


def validate_table_name(table: str) -> str:
    """Validate a SQLite table identifier against the strict allowlist regex."""
    if not isinstance(table, str) or TABLE_NAME_RE.fullmatch(table) is None:
        raise LoaderError(f"Invalid SQLite table name: {table!r}")
    return table


def _resolve_input_file(path: Path | str) -> Path:
    try:
        resolved = Path(path).resolve(strict=True)
    except OSError as exc:
        raise LoaderError(f"Input file not found: {path}") from exc
    if not resolved.is_file():
        raise LoaderError(f"Input path is not a regular file: {path}")
    return resolved


def open_sqlite_readonly(path: Path | str) -> sqlite3.Connection:
    """Open a SQLite database strictly in read-only mode with PRAGMA query_only=ON."""
    resolved = _resolve_input_file(path)
    uri = f"{resolved.as_uri()}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        raise LoaderError(f"Unable to open SQLite database read-only: {path}") from exc
    try:
        conn.execute("PRAGMA query_only = ON")
    except sqlite3.Error as exc:
        conn.close()
        raise LoaderError(f"Unable to enforce read-only PRAGMA on {path}") from exc
    return conn


def _verify_sqlite_table(conn: sqlite3.Connection, table: str) -> str:
    validated = validate_table_name(table)
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
        (validated,),
    ).fetchone()
    if row is None:
        raise LoaderError(f"SQLite table not found: {validated!r}")
    return str(row[0])


def _get_sqlite_columns(conn: sqlite3.Connection, verified_table: str) -> list[str]:
    rows = conn.execute(f'PRAGMA table_info("{verified_table}")').fetchall()
    return [str(col[1]) for col in rows]


def _validate_required_columns(columns: list[str], source_label: str) -> None:
    missing = [col for col in REQUIRED_COLUMNS if col not in columns]
    if missing:
        raise LoaderError(f"Missing required columns in {source_label}: {', '.join(missing)}")


def load_csv(path: Path | str) -> list[Record]:
    """Load and validate records from a CSV file."""
    resolved = _resolve_input_file(path)
    try:
        with resolved.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None:
                raise LoaderError(f"CSV file has no header row: {resolved.name}")
            columns = list(reader.fieldnames)
            _validate_required_columns(columns, resolved.name)

            records: list[Record] = []
            for row_num, row in enumerate(reader, start=2):
                if None in row or any(row[col] is None for col in REQUIRED_COLUMNS):
                    raise LoaderError(f"Malformed CSV row {row_num} in {resolved.name}")
                try:
                    record = Record(
                        id=row["id"],
                        date=row["date"],
                        counterparty=row["counterparty"],
                        amount=row["amount"],
                        currency=row["currency"],
                        reference=row["reference"],
                    )
                except ValidationError as exc:
                    raise LoaderError(
                        f"Invalid CSV row {row_num} in {resolved.name}: {exc}"
                    ) from exc
                records.append(record)
    except UnicodeDecodeError as exc:
        raise LoaderError(f"Unable to decode CSV file {resolved.name} as UTF-8") from exc
    except csv.Error as exc:
        raise LoaderError(f"CSV parse error in {resolved.name}: {exc}") from exc
    return records


def load_sqlite(path: Path | str, table: str) -> list[Record]:
    """Load and validate records from a verified read-only SQLite table."""
    validate_table_name(table)
    with contextlib.closing(open_sqlite_readonly(path)) as conn:
        verified_table = _verify_sqlite_table(conn, table)
        columns = _get_sqlite_columns(conn, verified_table)
        _validate_required_columns(columns, verified_table)

        cols = ", ".join(REQUIRED_COLUMNS)
        # verified_table passed TABLE_NAME_RE allowlist and sqlite_master lookup.
        query = f'SELECT {cols} FROM "{verified_table}"'  # noqa: S608
        records: list[Record] = []
        for row_num, row in enumerate(conn.execute(query), start=1):
            try:
                record = Record(
                    id=row[0],
                    date=row[1],
                    counterparty=row[2],
                    amount=row[3],
                    currency=row[4],
                    reference=row[5],
                )
            except ValidationError as exc:
                raise LoaderError(
                    f"Invalid SQLite row {row_num} in {verified_table}: {exc}"
                ) from exc
            records.append(record)
    return records


def load_records(path: Path | str, table: str | None = None) -> list[Record]:
    """Load records from a CSV or SQLite source based on file suffix."""
    suffix = Path(path).suffix.lower()
    if suffix == ".csv":
        return load_csv(path)
    if suffix in SQLITE_SUFFIXES:
        if table is None:
            raise LoaderError("SQLite input requires a table name")
        return load_sqlite(path, table)
    raise LoaderError(f"Unsupported input file type: {suffix!r}")


def inspect_source(path: Path | str, table: str | None = None) -> SourceInfo:
    """Return read-only metadata (kind, row count, columns) for a CSV or SQLite source."""
    suffix = Path(path).suffix.lower()
    if suffix == ".csv":
        resolved = _resolve_input_file(path)
        try:
            with resolved.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                if reader.fieldnames is None:
                    raise LoaderError(f"CSV file has no header row: {resolved.name}")
                columns = list(reader.fieldnames)
                _validate_required_columns(columns, resolved.name)
                row_count = 0
                for row_num, row in enumerate(reader, start=2):
                    if None in row or any(row[col] is None for col in REQUIRED_COLUMNS):
                        raise LoaderError(f"Malformed CSV row {row_num} in {resolved.name}")
                    row_count += 1
        except UnicodeDecodeError as exc:
            raise LoaderError(f"Unable to decode CSV file {resolved.name} as UTF-8") from exc
        except csv.Error as exc:
            raise LoaderError(f"CSV parse error in {resolved.name}: {exc}") from exc
        return SourceInfo(kind="csv", rows=row_count, columns=columns)

    if suffix in SQLITE_SUFFIXES:
        if table is None:
            raise LoaderError("SQLite input requires a table name")
        validate_table_name(table)
        with contextlib.closing(open_sqlite_readonly(path)) as conn:
            verified_table = _verify_sqlite_table(conn, table)
            columns = _get_sqlite_columns(conn, verified_table)
            _validate_required_columns(columns, verified_table)
            # verified_table passed TABLE_NAME_RE allowlist and sqlite_master lookup.
            count_row = conn.execute(
                f'SELECT COUNT(*) FROM "{verified_table}"'  # noqa: S608
            ).fetchone()
            row_count = int(count_row[0]) if count_row is not None else 0
        return SourceInfo(kind="sqlite", rows=row_count, columns=columns)

    raise LoaderError(f"Unsupported input file type: {suffix!r}")
