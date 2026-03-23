# core-py — Python Reference Implementation

The Python reference implementation of the AEGIS governance enforcement engine.

## Status

**Pre-alpha** — Module stubs with AGP-1 protocol documentation. No functional enforcement yet.

## Structure

```
aegis_core/
├── __init__.py      # Package root, version
├── gateway.py       # Governance gateway (ACTION_PROPOSE → DECISION_RESPONSE)
├── capability.py    # Capability registry (declarations and permission grants)
├── policy.py        # Policy engine (rule evaluation with fail-safe precedence)
├── risk.py          # Risk scoring engine (multi-dimensional risk assessment)
└── audit.py         # Audit logging (immutable governance decision records)
```

## Quickstart

```bash
# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest
```

## Design Principles

- **Stdlib only** — No external dependencies in the core package. Dev tools (pytest, ruff, mypy) are optional.
- **Type hints everywhere** — Full type annotations for all public APIs.
- **AGP-1 aligned** — Every module documents its role in the AEGIS Governance Protocol.
- **Reference, not production** — This implementation prioritizes correctness and clarity over performance. The Rust port (core-rs) will be the production runtime.
