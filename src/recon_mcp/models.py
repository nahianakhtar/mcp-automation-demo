"""Pydantic data models for recon-mcp."""

from __future__ import annotations

from datetime import date, datetime
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

CENT = Decimal("0.01")


def quantize_amount(value: object) -> Decimal:
    """Parse and quantize a monetary value to 0.01 using ROUND_HALF_EVEN."""
    if isinstance(value, bool | float):
        raise ValueError("amount must be a Decimal, int, or numeric string, not float or bool")
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("amount must not be empty")
        try:
            dec = Decimal(text)
        except InvalidOperation as exc:
            raise ValueError(f"invalid monetary amount: {value!r}") from exc
    elif isinstance(value, Decimal | int):
        try:
            dec = Decimal(value)
        except InvalidOperation as exc:
            raise ValueError(f"invalid monetary amount: {value!r}") from exc
    else:
        raise ValueError("amount must be a Decimal, int, or numeric string")

    if not dec.is_finite():
        raise ValueError("amount must be finite")
    return dec.quantize(CENT, rounding=ROUND_HALF_EVEN)


class Record(BaseModel):
    """Normalized invoice or expense ledger record."""

    model_config = ConfigDict(frozen=True)

    id: str
    date: date
    counterparty: str
    amount: Decimal
    currency: str
    reference: str = ""

    @field_validator("id", "counterparty", mode="before")
    @classmethod
    def _strip_required_text(cls, value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("field must be a string")
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("field must not be empty")
        return cleaned

    @field_validator("date", mode="before")
    @classmethod
    def _parse_iso_date(cls, value: object) -> date:
        if isinstance(value, datetime):
            raise ValueError("date must be an ISO-8601 calendar date, not datetime")
        if isinstance(value, date):
            return value
        if isinstance(value, str):
            cleaned = value.strip()
            if not cleaned:
                raise ValueError("date must not be empty")
            return date.fromisoformat(cleaned)
        raise ValueError("date must be an ISO-8601 date string or date")

    @field_validator("amount", mode="before")
    @classmethod
    def _validate_amount(cls, value: object) -> Decimal:
        return quantize_amount(value)

    @field_validator("currency", mode="before")
    @classmethod
    def _normalize_currency(cls, value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("currency must be a string")
        cleaned = value.strip().upper()
        if not cleaned:
            raise ValueError("currency must not be empty")
        return cleaned

    @field_validator("reference", mode="before")
    @classmethod
    def _normalize_reference(cls, value: object) -> str:
        if value is None:
            return ""
        if not isinstance(value, str):
            raise ValueError("reference must be a string")
        return value.strip()


class Match(BaseModel):
    """Matched invoice and expense pair."""

    model_config = ConfigDict(frozen=True)

    invoice_id: str
    expense_id: str
    reason: Literal["reference", "counterparty"]
    amount_delta: Decimal
    date_delta_days: int
    currency: str

    @field_validator("amount_delta", mode="before")
    @classmethod
    def _validate_amount_delta(cls, value: object) -> Decimal:
        return quantize_amount(value)


class ReconTotals(BaseModel):
    """String-formatted monetary totals for a reconciliation report."""

    model_config = ConfigDict(frozen=True)

    invoices: str
    expenses: str
    delta: str


class ReconReport(BaseModel):
    """Complete deterministic reconciliation result."""

    model_config = ConfigDict(frozen=True)

    matched: list[Match]
    unmatched_invoices: list[Record]
    unmatched_expenses: list[Record]
    totals: ReconTotals


class ExportResult(BaseModel):
    """Result of an export operation or dry run."""

    model_config = ConfigDict(frozen=True)

    written: bool
    path: str
    rows: int
    sha256: str


class SourceInfo(BaseModel):
    """Metadata summary returned by inspect_source."""

    model_config = ConfigDict(frozen=True)

    kind: Literal["csv", "sqlite"]
    rows: int
    columns: list[str]


class AuditEvent(BaseModel):
    """Single JSONL audit log entry."""

    model_config = ConfigDict(frozen=True)

    ts: str
    actor: Literal["cli", "mcp"]
    tool: str
    mode: Literal["read", "write"]
    dry_run: bool
    args: dict[str, str | int | bool | None] = Field(default_factory=dict)
    inputs_sha256: dict[str, str] = Field(default_factory=dict)
    outcome: Literal["ok", "denied", "error"]
    error: str | None = None
    result_sha256: str | None = None
