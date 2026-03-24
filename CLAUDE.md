# CLAUDE.md — aegis-core

## Project
The AEGIS governance enforcement engine — a dual-language runtime that evaluates AI governance policies in real time. Python serves as the reference implementation for rapid iteration and correctness validation; Rust will be the production runtime for performance-critical deployments.

## Org Context
- GitHub Org: github.com/aegis-initiative
- IP Owner: Finnoybu IP LLC
- Parent Ecosystem: Finnoybu Holdings LLC
- Domain: aegis-platform.net

## This Repo's Role
aegis-core is the computational heart of AEGIS. It implements the AEGIS Governance Protocol (AGP-1) message processing pipeline: receiving ACTION_PROPOSE messages from governed AI systems, evaluating them against registered policies and risk models, and returning DECISION_RESPONSE messages with approve/deny/escalate verdicts. It is consumed by aegis-platform as a library and is independently testable.

## Dual-Language Strategy
- **core-py/** — Python reference implementation (active development). Used for prototyping, correctness validation, and environments where Python is the runtime. All new governance logic lands here first.
- **core-rs/** — Rust production runtime (future). A faithful port of core-py optimized for low-latency, high-throughput policy evaluation. Will share the same JSON Schema interfaces and pass the same integration test suite.
- **schemas/** — Language-agnostic JSON Schema definitions shared between both implementations. These are the canonical interface contracts.

## Package Structure (core-py)
```
core-py/aegis_core/
├── gateway.py     — Governance gateway: receives ACTION_PROPOSE, dispatches to pipeline, returns DECISION_RESPONSE
├── capability.py  — Capability registry: manages capability declarations and permission grants
├── policy.py      — Policy engine: evaluates governance policies against proposed actions
├── risk.py        — Risk scoring engine: computes risk scores for proposed actions
└── audit.py       — Audit logging: immutable record of all governance decisions
```

## Governance Runtime Architecture
The enforcement pipeline follows the AGP-1 protocol flow:
1. **Gateway** receives an ACTION_PROPOSE message from a governed system
2. **Capability Registry** verifies the system has declared the relevant capabilities
3. **Policy Engine** evaluates all applicable policies against the proposed action
4. **Risk Engine** computes a composite risk score
5. **Gateway** synthesizes results into a DECISION_RESPONSE (approve/deny/escalate)
6. **Audit Logger** records the full decision chain for compliance

## Related Repos
- **aegis** (aegis-initiative/aegis) — Governance specs, ADRs, and JSON Schema definitions that this engine implements
- **aegis-platform** (aegis-initiative/aegis-platform) — Production platform that consumes this engine as a library
- **aegis-sdk** (aegis-initiative/aegis-sdk) — Client SDK that exposes a subset of this engine's capabilities
- **aegis-ops** (aegis-initiative/aegis-ops) — CI/CD workflows, deployment configs, infrastructure
- **aegis-labs** (aegis-initiative/aegis-labs) — Experimental versions and research spikes for new scoring models

## Stack
- **Python 3.11+** — Reference implementation (stdlib only during initial development)
- **Rust** (future) — Production runtime
- **JSON Schema** — Cross-language interface contracts
- **pytest** — Python test framework

## Key Conventions
- All public APIs must have corresponding JSON Schema definitions in aegis (the specs repo)
- Python code follows PEP 8; use type hints everywhere
- Unit tests required for all scoring functions (pytest)
- Each Python module has a docstring explaining its AGP-1 role
- Branch: main is protected; all changes via PR with 1 required review
- Commit style: conventional commits (feat:, docs:, chore:, fix:)

## Current Focus
Scaffolding the dual-language repo structure and defining the Python reference implementation module stubs with AGP-1 protocol documentation