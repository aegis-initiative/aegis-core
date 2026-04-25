# AEGIS Runtime — Python Reference Implementation

![Python](https://img.shields.io/badge/python-3.11+-blue)
![Status](https://img.shields.io/badge/status-alpha-orange)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Tests](https://img.shields.io/badge/tests-419%20passing-brightgreen)

The AEGIS Runtime is the **reference Python implementation** of the AEGIS
governance architecture. It provides a deterministic enforcement layer that
evaluates and governs AI-initiated actions **before they interact with
infrastructure**.

> **Capability without constraint is not intelligence™**

---

## What AEGIS Does

AEGIS sits between AI systems and the external world, enforcing governance
decisions before actions are executed:

```text
AI Agent
   │
   ▼ ACTION_PROPOSE
GovernanceGateway
   │
   ▼
DecisionEngine
 ├─ CapabilityRegistry    ← is this agent permitted?
 ├─ PolicyEngine          ← what do governance rules say?
 ├─ RiskEngine            ← what is the operational risk?
 └─ AuditSystem           ← immutable decision record
   │
   ▼ DECISION_RESPONSE
ToolProxy → External Systems
```

AEGIS ensures that:

- agents can only attempt actions they have **capabilities** for
- actions must pass **deterministic policy evaluation**
- high-risk actions trigger **escalation or confirmation**
- every governance decision is **immutably audited**

---

## Installation

```bash
git clone https://github.com/aegis-initiative/aegis-core.git
cd aegis-core/core-py
pip install -e ".[dev]"
```

After installation, the runtime can be imported as:

```python
from aegis_core import AEGISRuntime
```

---

## Quick Start

```python
from aegis_core import (
    AEGISRuntime,
    Capability,
    Policy,
    PolicyEffect,
    ActionType,
)

runtime = AEGISRuntime()

# Register a capability
runtime.capabilities.register(
    Capability(
        id="cap-read-docs",
        name="Read documentation",
        description="Allows reading documentation files",
        action_types=[ActionType.FILE_READ],
        target_patterns=["/docs/*"],
    )
)

# Grant capability to agent
runtime.capabilities.grant("agent-1", "cap-read-docs")

# Add an allow policy
runtime.policies.add_policy(
    Policy(
        id="allow-docs",
        name="Allow documentation reads",
        description="Agents may read documentation",
        effect=PolicyEffect.ALLOW,
        conditions=[],
    )
)

# Create governed tool proxy
proxy = runtime.create_tool_proxy("agent-1", "session-1")

proxy.register_tool(
    "read_file",
    fn=lambda path: open(path).read(),
    target="/docs/read",
)

content = proxy.call("read_file", path="/docs/intro.md")
```

If governance denies the action, the call raises a `PermissionError`.

---

## Running Tests

```bash
pytest
```

The test suite includes 419 tests: core module tests, integration tests,
and a comprehensive security test suite with 100% ATX-1 technique coverage.

---

## Development Setup

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Development tools:

```bash
pytest                  # Run tests
ruff check .            # Lint
ruff format .           # Format
mypy aegis_core/        # Type check
```

---

## Package Structure

```text
core-py/
├── aegis_core/           # Core runtime package
│   ├── gateway.py        # Governance gateway (entry point)
│   ├── decision_engine.py # Three-stage evaluation pipeline
│   ├── capability_registry.py # Capability-based access control
│   ├── policy_engine.py  # Deterministic policy evaluation
│   ├── risk.py           # Five-dimension risk scoring
│   ├── audit.py          # Immutable SQLite audit trail
│   ├── tool_proxy.py     # Tool interception layer
│   ├── protocol.py       # AGP-1 wire protocol
│   ├── exceptions.py     # Structured error hierarchy
│   └── errors.py         # Error code catalog
├── tests/                # Test suite (419 tests)
├── data/                 # Coverage and test data
└── pyproject.toml        # Package configuration
```

---

## Design Principles

### Deterministic Governance

The same request against the same policies always produces the same decision.

### Defense in Depth

Enforcement layers include capability checks, policy evaluation, risk scoring,
and audit recording.

### Default-Deny Security

Actions are denied unless explicitly allowed by both a capability grant and a
matching policy.

### Immutable Audit Trail

All governance decisions are permanently recorded in an append-only store.

### Protocol-First Architecture

Governance interactions are defined using structured AGP-1 protocol messages
with full JSON serialization.

---

## License & Trademark

Licensed under the [Apache License 2.0](LICENSE). See LICENSE for details.

AEGIS™ and **"Capability without constraint is not intelligence™"** are trademarks of **AEGIS Operations LLC**.
