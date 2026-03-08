<p align="center">
  <img src="assets/AEGIS_logo_aegis-core.svg" width="80" alt="AEGIS™ Core">
</p>

<p align="center">
  <strong>aegis-core</strong><br>
  The AEGIS™ enforcement engine — risk scoring, mediation layer, and policy runtime
</p>

<p align="center">
  <a href="https://github.com/aegis-initiative"><img src="https://img.shields.io/badge/org-aegis--initiative-0084e7?style=flat-square&logo=github" alt="Org"></a>
  <a href="https://aegissystems.app"><img src="https://img.shields.io/badge/domain-aegissystems.app-0084e7?style=flat-square" alt="Domain"></a>
  <img src="https://img.shields.io/badge/build-passing-brightgreen?style=flat-square" alt="Build">
  <img src="https://img.shields.io/badge/coverage-tracked-blue?style=flat-square" alt="Coverage">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-green?style=flat-square" alt="License"></a>
  <img src="https://img.shields.io/badge/ip--owner-Finnoybu%20IP%20LLC-blueviolet?style=flat-square" alt="IP Owner">
</p>

---

## Overview

`aegis-core` is the computational heart of the AEGIS™ governance architecture. It implements the **governance runtime layer** that enforces deterministic control over AI-generated actions before they interact with operational infrastructure.

> **Capability without constraint is not intelligence™**

---

## Architecture

```
AI Agent
   │
   ▼ ACTION_PROPOSE
AEGIS™ Governance Gateway       ← aegis-core entry point
   │
   ▼
Decision Engine
 ├ Capability Registry          ← is this action permitted?
 ├ Authority Verification       ← is this actor authorized?
 ├ Risk Scoring Engine          ← what is the operational risk?
 └ Policy Engine                ← what do governance rules say?
   │
   ▼ DECISION_RESPONSE
   │  (ALLOW | DENY | ESCALATE | REQUIRE_CONFIRMATION)
   ▼
Tool Proxy Layer
   │
   ▼ EXECUTION_RESULT
External Systems
```

---

## Core Components

### Governance Gateway
The entry point for all governance evaluation. Receives `ACTION_PROPOSE` messages and returns `DECISION_RESPONSE` outcomes.

### Decision Engine
Orchestrates the evaluation pipeline — capability check, authority verification, risk scoring, and policy evaluation — and produces a deterministic governance decision.

### Capability Registry
Maintains the defined set of operations AI systems are permitted to perform. Implements the constitutional default-deny model.

### Policy Engine
Evaluates governance rules against proposed actions. Supports `ALLOW`, `DENY`, `ESCALATE`, and `REQUIRE_CONFIRMATION` outcomes.

### Risk Scoring Engine
Assesses the operational impact of proposed actions based on the AEGIS Risk Scoring Model (AGP-1).

### Tool Proxy Layer
Mediates execution of approved actions through a controlled interface to external systems.

### Audit Engine
Produces immutable audit records for all governance decisions, enabling forensic analysis and compliance reporting.

---

## Protocol

`aegis-core` implements the **AEGIS Governance Protocol (AGP-1)**:

```
AI Agent → ACTION_PROPOSE
AEGIS™   → DECISION_RESPONSE
Tool Proxy → EXECUTION_RESULT
```

Governance outcomes:
```
ALLOW                 # Action approved, execute
DENY                  # Action rejected, block
ESCALATE              # Requires elevated review
REQUIRE_CONFIRMATION  # Requires explicit human approval
```

Protocol specifications: [`aegis/rfc/`](https://github.com/aegis-initiative/aegis)

---

## JSON Schemas

`aegis-core` validates all governance messages against JSON Schema definitions:

```
schemas/
├── agp/
│   ├── action_propose.schema.json
│   ├── decision_response.schema.json
│   ├── escalation_request.schema.json
│   └── execution_result.schema.json
├── capability/
│   └── capability.schema.json
└── governance/
    └── events/
        ├── circumvention_report.schema.json
        ├── governance_attestation.schema.json
        ├── incident_notice.schema.json
        ├── policy_update.schema.json
        └── risk_signal.schema.json
```

---

## Related Repositories

| Repo | Relationship |
|---|---|
| [aegis](https://github.com/aegis-initiative/aegis) | Architectural specs and schemas this engine implements |
| [aegis-platform](https://github.com/aegis-initiative/aegis-platform) | Production platform that consumes this engine |
| [aegis-sdk](https://github.com/aegis-initiative/aegis-sdk) | Client SDK exposing a subset of this engine's capabilities |
| [aegis-labs](https://github.com/aegis-initiative/aegis-labs) | Research sandbox for experimental scoring models |
| [aegis-constitution](https://github.com/aegis-initiative/aegis-constitution) | Constitutional articles this engine enforces |

---

## License & Trademark

Licensed under the [Apache License 2.0](LICENSE).

AEGIS™ and **"Capability without constraint is not intelligence™"** are trademarks of **Finnoybu IP LLC**.
