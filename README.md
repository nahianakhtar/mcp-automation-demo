# recon-mcp

Offline invoice and expense reconciliation CLI (`recon`) and MCP stdio server (`mcp==2.3.0`, `MCPServer`) with deterministic `Decimal` matching, strict read/write guardrails, and append-only JSONL audit logging.

## Key Capabilities & Guardrails

- **Input sources**: Reads CSV (`.csv`) and SQLite (`.sqlite`, `.db`) inputs with required columns `id, date, counterparty, amount, currency, reference`. SQLite connections open read-only (`mode=ro` + `PRAGMA query_only = ON`) and validate table names against `^[A-Za-z_][A-Za-z0-9_]{0,63}$` and `sqlite_master`; no caller-supplied SQL is executed.
- **Deterministic `Decimal` matching**: Parses amounts with `decimal.Decimal` (never `float`), quantized to `0.01` using `ROUND_HALF_EVEN`. Matches in order: (1) exact `reference` within `tolerance`, then (2) casefolded `counterparty` within `tolerance` and `window_days`. Currency mismatches never match; ties break deterministically by smallest amount delta, smallest date delta, and `id`.
- **Policy-enforced guardrails**:
  - Read-only by default (`allow_write=False` unless `--allow-write` or `RECON_ALLOW_WRITE=1`).
  - Exports run as dry runs by default (`written=False`) unless both `allow_write` and `--apply` / `apply=True` are set.
  - Read paths must resolve to regular files `<= 50 MiB` (and stay inside `RECON_READ_ROOT` when configured).
  - Write paths must stay inside `--write-root` / `RECON_WRITE_ROOT` (default `./out`), use `.csv` or `.json`, reject symlinks and path traversal, refuse to overwrite existing files, and write atomically via temp file + `os.replace`.
  - No delete tool and no network calls (`open_world_hint=False` on all MCP tools).
- **JSONL audit log**: Appends one sanitized, `flush` + `os.fsync` record per CLI or MCP call (including denials and errors) to `./.recon/audit.jsonl` (override with `--audit-log` or `RECON_AUDIT_LOG`), logging file SHA-256 digests and path/option metadata without monetary amounts or row contents.

## Requirements

- Python `>= 3.12`
- [`uv`](https://docs.astral.sh/uv/) (dependencies are pinned in `pyproject.toml` and `uv.lock`)

## Quickstart

Install dependencies from the lockfile:

```bash
uv sync --locked
```

Run reconciliation on the included sample fixtures:

```bash
.venv/bin/recon reconcile \
  --invoices tests/fixtures/invoices.csv \
  --expenses tests/fixtures/expenses.csv
```

Observed output on the sample fixtures (exits `1` because unmatched rows remain; pass `--json` for `ReconReport` JSON):

```text
matched=3 unmatched_invoices=2 unmatched_expenses=2
totals: invoices=2799.95 expenses=2119.95 delta=680.00
```

Preview an export as a dry run (default behavior):

```bash
.venv/bin/recon export \
  --invoices tests/fixtures/invoices.csv \
  --expenses tests/fixtures/expenses.csv \
  --out report.json
```

Write an exported `.csv` or `.json` report inside `--write-root` (default `./out`) by explicitly enabling both `--allow-write` and `--apply`:

```bash
.venv/bin/recon export \
  --invoices tests/fixtures/invoices.csv \
  --expenses tests/fixtures/expenses.csv \
  --out report.json \
  --allow-write \
  --apply
```

Start the MCP stdio server (stdout is reserved strictly for MCP protocol messages):

```bash
.venv/bin/recon serve
```

`recon serve` also accepts `--allow-write`, `--write-root DIR`, and `--audit-log PATH`, as well as environment variables `RECON_ALLOW_WRITE=1`, `RECON_WRITE_ROOT`, `RECON_READ_ROOT`, and `RECON_AUDIT_LOG`.

## MCP Tools

| Tool | Arguments | Annotations |
|---|---|---|
| `inspect_source` | `path: str`, `table: str \| None = None` | `read_only_hint=True`, `open_world_hint=False` |
| `reconcile` | `invoices: str`, `expenses: str`, `table_invoices: str \| None = None`, `table_expenses: str \| None = None`, `tolerance: str = "0.00"`, `window_days: int = 3` | `read_only_hint=True`, `open_world_hint=False` |
| `export_report` | `invoices: str`, `expenses: str`, `out: str`, `apply: bool = False` | `read_only_hint=False`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=False` |
| `audit_tail` | `n: int = 20` (`1 <= n <= 200`) | `read_only_hint=True`, `open_world_hint=False` |

## CLI Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success (`reconcile`: all rows matched; `export` / `serve`: ok) |
| `1` | `reconcile` completed with unmatched invoices or expenses |
| `2` | Usage error or invalid input/file format |
| `3` | Guardrail policy denied the operation |

## Lint & Offline Tests

Run lint, format check, and the offline pytest suite directly from `.venv`:

```bash
.venv/bin/ruff check . && .venv/bin/ruff format --check . && PYTHONPATH=src .venv/bin/pytest -q
```

Or via `uv` in offline mode after `uv sync --locked`:

```bash
UV_OFFLINE=1 uv run --offline ruff check . && UV_OFFLINE=1 uv run --offline ruff format --check . && UV_OFFLINE=1 uv run --offline pytest -q
```

`tests/conftest.py` installs an autouse socket guard blocking `AF_INET` and `AF_INET6` connections so the entire test suite runs offline.
