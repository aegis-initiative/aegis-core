# CLAUDE.md — aegis-core

## Project

The AEGIS governance enforcement engine — a dual-language runtime that evaluates
AI governance policies in real time. Python serves as the reference implementation
for rapid iteration and correctness validation; Rust will be the production
runtime for performance-critical deployments.

## Org Context

- GitHub Org: github.com/aegis-initiative
- Operating Entity: AEGIS Operations LLC
- Trademark Owner: AEGIS Operations LLC
- Domain: aegis-platform.net

## This Repo's Role

aegis-core is the computational heart of AEGIS. It implements the AEGIS
Governance Protocol (AGP-1) message processing pipeline: receiving
ACTION_PROPOSE messages from governed AI systems, evaluating them against
registered policies and risk models, and returning DECISION_RESPONSE messages
with approve/deny/escalate verdicts. It is consumed by aegis-platform as a
library and is independently testable.

## Dual-Language Strategy

- **core-py/** — Python reference implementation (active development). Used for
  prototyping, correctness validation, and environments where Python is the
  runtime. All new governance logic lands here first.
- **core-rs/** — Rust production runtime (future). A faithful port of core-py
  optimized for low-latency, high-throughput policy evaluation. Will share the
  same JSON Schema interfaces and pass the same integration test suite.
- **schemas/** — Language-agnostic JSON Schema definitions shared between both
  implementations. These are the canonical interface contracts.

## Package Structure (core-py)

```text
core-py/aegis_core/
├── gateway.py            — Governance gateway: validates requests, dispatches to pipeline
├── decision_engine.py    — Three-stage evaluation: capability → policy → risk
├── capability_registry.py — Capability-based access control with temporal expiry
├── policy_engine.py      — Deterministic policy evaluation (deny > escalate > allow)
├── risk.py               — Five-dimension risk scoring with evasion protections
├── audit.py              — Immutable SQLite audit trail (append-only)
├── tool_proxy.py         — Tool interception layer (sync + async, recursion guards)
├── protocol.py           — AGP-1 wire protocol with JSON serialization
├── exceptions.py         — Stripe-style structured error hierarchy
└── errors.py             — Error code catalog (AEGIS-{CAT}-{NNN} format)
```

## Governance Runtime Architecture

The enforcement pipeline follows the AGP-1 protocol flow:

1. **Gateway** receives an ACTION_PROPOSE message from a governed system
2. **Capability Registry** verifies the agent holds the required capability
3. **Policy Engine** evaluates all applicable policies (deny > escalate > allow)
4. **Risk Engine** computes a composite risk score across five dimensions
5. **Decision Engine** synthesizes results into a DECISION_RESPONSE
6. **Audit System** records the full decision chain immutably

## Related Repos

- **aegis** (aegis-initiative/aegis) — Governance specs, ADRs, and JSON Schema
  definitions that this engine implements
- **aegis-platform** (aegis-initiative/aegis-platform) — Production platform
  that consumes this engine as a library
- **aegis-sdk** (aegis-initiative/aegis-sdk) — Client SDK that exposes a
  subset of this engine's capabilities
- **aegis-ops** (aegis-initiative/aegis-ops) — CI/CD workflows, deployment
  configs, infrastructure
- **aegis-labs** (aegis-initiative/aegis-labs) — Experimental versions and
  research spikes for new scoring models

## Stack

- **Python 3.11+** — Reference implementation (stdlib only, zero dependencies)
- **Rust** (future) — Production runtime
- **JSON Schema** — Cross-language interface contracts
- **pytest** — Python test framework (419 tests, 100% ATX-1 coverage)

## Key Conventions

- All public APIs must have corresponding JSON Schema definitions in aegis
- Python code follows PEP 8; use type hints everywhere
- Unit tests required for all scoring functions (pytest)
- Each Python module has a docstring explaining its AGP-1 role
- Branch: main is protected; all changes via PR with 1 required review
- Commit style: conventional commits (feat:, docs:, chore:, fix:)

## Current Focus

v0.1.x is feature-complete and security-hardened (9-round red/blue team
adversarial assessment, 353+ tests). Current work focuses on documentation
polish, CI hardening, and preparing for the Rust port.
