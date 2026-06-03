# CLAUDE.md — aegis-core

## Identity

You maintain **aegis-core** — the computational heart of AEGIS and the canonical implementation of the AEGIS
Governance Protocol (AGP-1) enforcement engine. This is a dual-language runtime that evaluates AI governance
policies in real time: it receives `ACTION_PROPOSE` messages from governed AI systems, evaluates them against
registered policies and risk models, and returns `DECISION_RESPONSE` messages with approve/deny/escalate
verdicts. Python is the reference implementation (rapid iteration, correctness validation); Rust will be the
production runtime for performance-critical deployments. aegis-core is consumed by aegis-platform as a library
and is independently testable. Runtime logic lands here, not in sibling repos.

## Repository catalog

- `packages/core-py/` — Python reference implementation (active development). Prototyping, correctness
  validation, and Python-runtime environments. All new governance logic lands here first.
  - `packages/core-py/aegis_core/` — the governance runtime package (see architecture below)
  - `packages/core-py/data/` — runtime data manifests (`manifest.json`, `security-testing.json`)
  - `packages/core-py/tests/` — pytest suite (100% ATX-1 coverage)
  - `packages/core-py/scripts/` — build and maintenance scripts
- `packages/core-rs/` — Rust production runtime (future). A faithful port of core-py optimized for low-latency,
  high-throughput policy evaluation. Will share the same JSON Schema interfaces and pass the same integration
  test suite.
- `schemas/` — language-agnostic JSON Schema definitions shared between both implementations; the canonical
  interface contracts (not yet populated — added as AGP-1 interfaces stabilize)
- `docs/` — repository documentation
- `assets/` — logos and brand assets for this repo

### Package structure (`packages/core-py/aegis_core/`)

```text
packages/core-py/aegis_core/
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

The `aegis_core.governance` subpackage (Unreleased) compiles a single declarative AEGIS Governance Profile
(YAML or dict) to equivalent Cedar and Rego policies; subset parity with the `microsoft/agent-governance-toolkit`
community example is enforced by test.

### Governance runtime architecture (AGP-1 pipeline)

1. **Gateway** receives an `ACTION_PROPOSE` message from a governed system
2. **Capability Registry** verifies the agent holds the required capability
3. **Policy Engine** evaluates all applicable policies (deny > escalate > allow)
4. **Risk Engine** computes a composite risk score across five dimensions
5. **Decision Engine** synthesizes results into a `DECISION_RESPONSE`
6. **Audit System** records the full decision chain immutably

## Data registry

- **JSON Schema interface contracts (canonical)**: `schemas/` — `ACTION_PROPOSE` / `DECISION_RESPONSE` wire
  format, capability declarations, policy rule definitions, risk assessment results, audit records
- **Runtime data manifests**: `packages/core-py/data/` (`manifest.json`, `security-testing.json`)
- **Security testing record**: `packages/core-py/SECURITY_TESTING.md`

## Publication registry

- **PyPI package**: `aegis-core` (Python reference implementation, current `0.1.3`; published from
  `packages/core-py/`, `pip install`-able)
- **aegis-core concept DOI** (all versions): [10.5281/zenodo.19342904](https://doi.org/10.5281/zenodo.19342904)
- **aegis-core v0.1.2 version DOI**: [10.5281/zenodo.19355478](https://doi.org/10.5281/zenodo.19355478)
- **Changelog**: `packages/core-py/CHANGELOG.md` (Keep a Changelog format, synced with the AEGIS Initiative
  changelog)

## People & contacts

- **Primary maintainer**: Ken (sole maintainer during pre-ratification)
- **Reviewer routing**: `.github/CODEOWNERS`

## Identifier registry

- **GitHub Org**: [github.com/aegis-initiative](https://github.com/aegis-initiative)
- **Operating Entity**: AEGIS Operations LLC
- **Trademark Owner**: AEGIS Operations LLC (public attribution rule — internal IP-holder context lives in the
  workspace CLAUDE.md, never in public repo content)
- **Domain**: aegis-core.net
- **Protocol**: AGP-1 (AEGIS Governance Protocol)
- **Package version**: `aegis-core` 0.1.3 (PyPI / `packages/core-py/pyproject.toml`)
- **Error code format**: `AEGIS-{CAT}-{NNN}`
- **License**: Apache-2.0 (see repo `LICENSE`; full dual-license matrix in the workspace CLAUDE.md)

## Cross-repo pointers

- **aegis-governance** — architectural specs, RFCs, and JSON Schema definitions this engine implements
- **aegis-sdk** — client SDK that exposes a subset of this engine's capabilities
- **aegis-labs** — experimental versions and research spikes for new scoring models
- **aegis-ops** — CI/CD workflows, deployment configs, infrastructure
- **aegis-platform** — production platform that consumes this engine as a library

Ecosystem-wide structure and the full specialist-role matrix live in the workspace-level CLAUDE.md
(`d:/dev/AEGIS Initiative/CLAUDE.md`), inherited automatically — not duplicated here.

## Responsibilities

- Maintain the AGP-1 enforcement pipeline and its Python reference implementation
- Keep the JSON Schema contracts in `schemas/` canonical across both language implementations
- Preserve subset parity between `aegis_core.governance` and the published Microsoft AGT community example
- Maintain full ATX-1 coverage in the test suite
- Prepare the Rust production runtime as a faithful port of core-py

## Conventions specific to this repo

- **Stack**: Python 3.11+ reference implementation (stdlib only, zero runtime dependencies); Rust (future)
  production runtime; JSON Schema for cross-language interface contracts; pytest test framework (100% ATX-1
  coverage); ruff + mypy for lint and types
- All public APIs must have corresponding JSON Schema definitions in `schemas/`
- Python code follows PEP 8; use type hints everywhere
- Unit tests required for all scoring functions (pytest)
- Each Python module has a docstring explaining its AGP-1 role
- Branch: `main` protected, all changes via PR with 1 required review; conventional commits
  (`feat:`, `docs:`, `chore:`, `fix:`)

## Live state pointers

- **Active issues**: `gh issue list --repo aegis-initiative/aegis-core`
- **Recent activity**: `git log --since='14 days ago'`
- **Current version / unreleased work**: `packages/core-py/CHANGELOG.md`
- v0.1.x is feature-complete and security-hardened (multi-round red/blue adversarial assessment); current work
  focuses on documentation, CI hardening, and preparing the Rust port

## Addendum files

None yet. Create under `.claude/` when needed (e.g. `GOTCHAS.md`, `CONTACTS.md`).
