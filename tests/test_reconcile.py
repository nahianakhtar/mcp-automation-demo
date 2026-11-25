"""Unit tests for deterministic Decimal reconciliation."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from pathlib import Path

import pytest

from recon_mcp.loaders import load_csv
from recon_mcp.models import Record
from recon_mcp.reconcile import reconcile


def _rec(
    rec_id: str,
    rec_date: str,
    counterparty: str,
    amount: str | Decimal,
    currency: str = "USD",
    reference: str = "",
) -> Record:
    return Record(
        id=rec_id,
        date=rec_date,
        counterparty=counterparty,
        amount=amount,
        currency=currency,
        reference=reference,
    )


def test_reconcile_fixture_csvs(fixtures_dir: Path) -> None:
    invoices = load_csv(fixtures_dir / "invoices.csv")
    expenses = load_csv(fixtures_dir / "expenses.csv")

    report = reconcile(invoices, expenses)

    assert [(m.invoice_id, m.expense_id, m.reason) for m in report.matched] == [
        ("INV-001", "EXP-001", "reference"),
        ("INV-002", "EXP-002", "counterparty"),
        ("INV-004", "EXP-004", "reference"),
    ]
    assert [r.id for r in report.unmatched_invoices] == ["INV-003", "INV-005"]
    assert [r.id for r in report.unmatched_expenses] == ["EXP-003", "EXP-006"]
    assert report.totals.invoices == "2799.95"
    assert report.totals.expenses == "2119.95"
    assert report.totals.delta == "680.00"


def test_reconcile_decimal_round_half_even_and_negative_credits() -> None:
    invoices = [
        _rec("INV-A", "2026-01-01", "Vendor A", "0.005", reference="R1"),
        _rec("INV-B", "2026-01-01", "Vendor B", "0.015", reference="R2"),
        _rec("INV-C", "2026-01-01", "Vendor C", "-50.005", reference="R3"),
    ]
    expenses = [
        _rec("EXP-A", "2026-01-01", "Vendor A", "0.00", reference="R1"),
        _rec("EXP-B", "2026-01-01", "Vendor B", "0.02", reference="R2"),
        _rec("EXP-C", "2026-01-01", "Vendor C", "-50.00", reference="R3"),
    ]

    report = reconcile(invoices, expenses, tolerance="0.00")

    assert len(report.matched) == 3
    assert report.unmatched_invoices == []
    assert report.unmatched_expenses == []
    assert report.totals.invoices == "-49.98"
    assert report.totals.expenses == "-49.98"
    assert report.totals.delta == "0.00"


def test_reconcile_negative_zero_delta_normalized() -> None:
    invoices = [_rec("INV-1", "2026-01-01", "Acme", "-0.004", reference="R1")]
    expenses = [_rec("EXP-1", "2026-01-01", "Acme", "0.000", reference="R1")]

    report = reconcile(invoices, expenses)

    assert report.totals.invoices == "0.00"
    assert report.totals.expenses == "0.00"
    assert report.totals.delta == "0.00"


def test_reconcile_rejects_invalid_tolerance_and_window_days() -> None:
    with pytest.raises(ValueError, match="float"):
        reconcile([], [], tolerance=0.05)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="float"):
        reconcile([], [], tolerance=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="non-negative"):
        reconcile([], [], tolerance="-0.01")
    with pytest.raises(ValueError, match="non-negative integer"):
        reconcile([], [], window_days=-1)
    with pytest.raises(ValueError, match="non-negative integer"):
        reconcile([], [], window_days=True)


def test_reconcile_reference_precedes_counterparty_and_ignores_window() -> None:
    invoices = [
        _rec("INV-1", "2026-01-01", "Acme Corp", "100.00", reference="REF-1"),
    ]
    expenses = [
        _rec("EXP-CP", "2026-01-01", "Acme Corp", "100.00", reference=""),
        _rec("EXP-REF", "2026-06-01", "Different Name", "100.00", reference="REF-1"),
    ]

    report = reconcile(invoices, expenses, window_days=3)

    assert len(report.matched) == 1
    assert report.matched[0].invoice_id == "INV-1"
    assert report.matched[0].expense_id == "EXP-REF"
    assert report.matched[0].reason == "reference"
    assert [r.id for r in report.unmatched_expenses] == ["EXP-CP"]


def test_reconcile_empty_references_do_not_match_as_reference() -> None:
    invoices = [_rec("INV-1", "2026-01-01", "Alpha", "10.00", reference="")]
    expenses = [_rec("EXP-1", "2026-01-20", "Beta", "10.00", reference="")]

    report = reconcile(invoices, expenses, window_days=3)

    assert report.matched == []
    assert len(report.unmatched_invoices) == 1
    assert len(report.unmatched_expenses) == 1


@pytest.mark.parametrize(
    ("exp_amount", "expected_matched"),
    [
        ("100.00", True),
        ("100.05", True),
        ("99.95", True),
        ("100.06", False),
        ("99.94", False),
    ],
)
def test_reconcile_tolerance_boundaries(exp_amount: str, expected_matched: bool) -> None:
    invoices = [_rec("INV-1", "2026-01-10", "Acme", "100.00", reference="R1")]
    expenses = [_rec("EXP-1", "2026-01-10", "Acme", exp_amount, reference="R1")]

    report = reconcile(invoices, expenses, tolerance="0.05")

    assert (len(report.matched) == 1) is expected_matched


@pytest.mark.parametrize(
    ("exp_date", "window_days", "expected_matched"),
    [
        ("2026-01-13", 3, True),
        ("2026-01-07", 3, True),
        ("2026-01-14", 3, False),
        ("2026-01-06", 3, False),
        ("2026-01-10", 0, True),
        ("2026-01-11", 0, False),
    ],
)
def test_reconcile_date_window_boundaries(
    exp_date: str, window_days: int, expected_matched: bool
) -> None:
    invoices = [_rec("INV-1", "2026-01-10", "Acme Corp", "50.00", reference="")]
    expenses = [_rec("EXP-1", exp_date, "ACME CORP", "50.00", reference="")]

    report = reconcile(invoices, expenses, window_days=window_days)

    assert (len(report.matched) == 1) is expected_matched


def test_reconcile_deterministic_tie_breaks_and_input_order_invariance() -> None:
    # 1. Smallest Δamount wins over smaller Δdate and earlier ID.
    inv = _rec("INV-1", "2026-01-10", "Acme", "100.00")
    exp_closer_date = _rec("EXP-A", "2026-01-10", "Acme", "100.05")
    exp_closer_amt = _rec("EXP-B", "2026-01-12", "Acme", "100.01")
    r1 = reconcile([inv], [exp_closer_date, exp_closer_amt], tolerance="0.05", window_days=3)
    assert r1.matched[0].expense_id == "EXP-B"
    assert r1.matched[0].amount_delta == Decimal("0.01")

    # 2. Equal Δamount -> smallest Δdate wins over earlier ID.
    exp_farther_date = _rec("EXP-A", "2026-01-13", "Acme", "100.02")
    exp_nearer_date = _rec("EXP-B", "2026-01-11", "Acme", "100.02")
    r2 = reconcile([inv], [exp_farther_date, exp_nearer_date], tolerance="0.05", window_days=3)
    assert r2.matched[0].expense_id == "EXP-B"
    assert r2.matched[0].date_delta_days == 1

    # 3. Equal Δamount and Δdate -> lexicographically smallest id wins, regardless of input order.
    inv_a = _rec("INV-01", "2026-01-10", "Acme", "100.00")
    inv_b = _rec("INV-02", "2026-01-10", "Acme", "100.00")
    exp_x = _rec("EXP-01", "2026-01-10", "Acme", "100.00")
    exp_y = _rec("EXP-02", "2026-01-10", "Acme", "100.00")

    forward = reconcile([inv_a, inv_b], [exp_x, exp_y])
    reversed_inputs = reconcile([inv_b, inv_a], [exp_y, exp_x])
    assert forward == reversed_inputs
    assert [(m.invoice_id, m.expense_id) for m in forward.matched] == [
        ("INV-01", "EXP-01"),
        ("INV-02", "EXP-02"),
    ]


def test_reconcile_currency_mismatch_never_matches() -> None:
    invoices = [_rec("INV-1", "2026-01-10", "Gamma GmbH", "300.00", "EUR", "REF-1003")]
    expenses = [_rec("EXP-1", "2026-01-10", "Gamma GmbH", "300.00", "USD", "REF-1003")]

    report = reconcile(invoices, expenses, tolerance="10.00", window_days=30)

    assert report.matched == []
    assert [r.id for r in report.unmatched_invoices] == ["INV-1"]
    assert [r.id for r in report.unmatched_expenses] == ["EXP-1"]


def test_reconcile_empty_inputs() -> None:
    report = reconcile([], [])
    assert report.matched == []
    assert report.unmatched_invoices == []
    assert report.unmatched_expenses == []
    assert report.totals.invoices == "0.00"
    assert report.totals.expenses == "0.00"
    assert report.totals.delta == "0.00"
    assert isinstance(date(2026, 1, 1), date)
