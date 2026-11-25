"""Pure deterministic invoice and expense reconciliation using Decimal arithmetic."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from decimal import Decimal

from recon_mcp.models import Match, ReconReport, ReconTotals, Record, quantize_amount


def _format_money(value: Decimal) -> str:
    quantized = quantize_amount(value)
    if quantized == 0:
        quantized = Decimal("0.00")
    return f"{quantized:.2f}"


def reconcile(
    invoices: Sequence[Record],
    expenses: Sequence[Record],
    tolerance: Decimal | str | int = Decimal("0.00"),
    window_days: int = 3,
) -> ReconReport:
    """Reconcile invoices against expenses deterministically.

    Matching order:
    1. Exact non-empty reference, same currency, and |Δamount| <= tolerance.
    2. Casefolded counterparty, same currency, |Δamount| <= tolerance, and |Δdate| <= window_days.

    Ties are broken by smallest Δamount, then smallest Δdate, then invoice id, then expense id.
    Each record matches at most once.
    """
    tol = quantize_amount(tolerance)
    if tol < Decimal("0.00"):
        raise ValueError("tolerance must be non-negative")
    if isinstance(window_days, bool) or not isinstance(window_days, int) or window_days < 0:
        raise ValueError("window_days must be a non-negative integer")

    matched_inv: set[int] = set()
    matched_exp: set[int] = set()
    matches: list[Match] = []

    # Pass 1: exact reference match (same currency, non-empty reference, amount within tolerance).
    exp_by_ref: dict[tuple[str, str], list[tuple[int, Record]]] = defaultdict(list)
    for exp_idx, exp in enumerate(expenses):
        if exp.reference:
            exp_by_ref[(exp.currency, exp.reference)].append((exp_idx, exp))

    ref_candidates: list[tuple[Decimal, int, str, str, int, int, str]] = []
    for inv_idx, inv in enumerate(invoices):
        if not inv.reference:
            continue
        for exp_idx, exp in exp_by_ref.get((inv.currency, inv.reference), ()):
            abs_delta = quantize_amount(abs(inv.amount - exp.amount))
            if abs_delta <= tol:
                date_delta = abs((inv.date - exp.date).days)
                ref_candidates.append(
                    (abs_delta, date_delta, inv.id, exp.id, inv_idx, exp_idx, inv.currency)
                )

    ref_candidates.sort(key=lambda item: (item[0], item[1], item[2], item[3], item[4], item[5]))
    for abs_delta, date_delta, inv_id, exp_id, inv_idx, exp_idx, currency in ref_candidates:
        if inv_idx in matched_inv or exp_idx in matched_exp:
            continue
        matched_inv.add(inv_idx)
        matched_exp.add(exp_idx)
        matches.append(
            Match(
                invoice_id=inv_id,
                expense_id=exp_id,
                reason="reference",
                amount_delta=abs_delta,
                date_delta_days=date_delta,
                currency=currency,
            )
        )

    # Pass 2: casefolded counterparty match within tolerance and date window.
    exp_by_cp: dict[tuple[str, str], list[tuple[int, Record]]] = defaultdict(list)
    for exp_idx, exp in enumerate(expenses):
        if exp_idx not in matched_exp:
            exp_by_cp[(exp.currency, exp.counterparty.casefold())].append((exp_idx, exp))

    cp_candidates: list[tuple[Decimal, int, str, str, int, int, str]] = []
    for inv_idx, inv in enumerate(invoices):
        if inv_idx in matched_inv:
            continue
        for exp_idx, exp in exp_by_cp.get((inv.currency, inv.counterparty.casefold()), ()):
            abs_delta = quantize_amount(abs(inv.amount - exp.amount))
            date_delta = abs((inv.date - exp.date).days)
            if abs_delta <= tol and date_delta <= window_days:
                cp_candidates.append(
                    (abs_delta, date_delta, inv.id, exp.id, inv_idx, exp_idx, inv.currency)
                )

    cp_candidates.sort(key=lambda item: (item[0], item[1], item[2], item[3], item[4], item[5]))
    for abs_delta, date_delta, inv_id, exp_id, inv_idx, exp_idx, currency in cp_candidates:
        if inv_idx in matched_inv or exp_idx in matched_exp:
            continue
        matched_inv.add(inv_idx)
        matched_exp.add(exp_idx)
        matches.append(
            Match(
                invoice_id=inv_id,
                expense_id=exp_id,
                reason="counterparty",
                amount_delta=abs_delta,
                date_delta_days=date_delta,
                currency=currency,
            )
        )

    matches.sort(key=lambda m: (m.invoice_id, m.expense_id))
    unmatched_invoices = sorted(
        (inv for idx, inv in enumerate(invoices) if idx not in matched_inv),
        key=lambda r: (r.id, r.date),
    )
    unmatched_expenses = sorted(
        (exp for idx, exp in enumerate(expenses) if idx not in matched_exp),
        key=lambda r: (r.id, r.date),
    )

    inv_total = sum((r.amount for r in invoices), Decimal("0.00"))
    exp_total = sum((r.amount for r in expenses), Decimal("0.00"))
    totals = ReconTotals(
        invoices=_format_money(inv_total),
        expenses=_format_money(exp_total),
        delta=_format_money(inv_total - exp_total),
    )

    return ReconReport(
        matched=matches,
        unmatched_invoices=unmatched_invoices,
        unmatched_expenses=unmatched_expenses,
        totals=totals,
    )
