<!-- markdownlint-disable MD024 MD025 -->

# AEGIS Runtime Changelog

All notable changes to the AEGIS Runtime reference implementation will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and versions are synchronized with the main [AEGIS Initiative Changelog](../CHANGELOG.md).

---

# [0.1.2] — 2026-03-31

**Status:** STABLE — Production-ready reference implementation

## Added

- **Stripe-style descriptive errors** — structured error hierarchy with
  `AEGIS-{CAT}-{NNN}` error codes, `cause` field, auto-generated `help_url`,
  and `to_dict()` for JSON API responses. 37 error codes cataloged in
  `errors.py`, all 47 raise sites updated across 5 modules. (closes #3)
- **Python CI workflow** — `python-ci.yml` runs pytest + ruff + mypy on every
  push to `core-py/`
- **50 new error tests** — full coverage of structured error fields, serialization,
  help URL generation, and subclass inheritance

## Changed

- **CLAUDE.md** updated to reflect current codebase (was stale since scaffolding)
- **core-py/README.md** rewritten — fixed broken install sections, wrong import
  paths, outdated content, license badge
- **Root README.md** reformatted for markdownlint compliance

## Fixed

- **65 markdownlint errors** resolved across all 15 markdown files
- **167 ruff lint/format errors** resolved across 35 Python files
- **Spellcheck** — 24 technical terms added to `.cspell.json`
- **`__all__` exports** sorted per isort convention
- **Per-file ruff ignores** configured for test files (ambiguous unicode in
  security evasion tests is intentional, not a lint error)

## Stats

- 403 tests, all passing
- 5 CI workflows, all green (Docs Consistency, Docs Lint, Link Check,
  Python CI, Spellcheck)
- 0 open issues
- ATX-1: 25/25 applicable (100%)
- ATM-1: 6/6 applicable (100%)

## Deferred to v0.2.0 (Rust port)

- Rust production runtime (`core-rs/`)
- Agent identity authentication (RFC-0002 transport layer)
- Parameter semantic analysis (NLP/policy DSL)
- Policy condition sandboxing
- Persistent replay detection

---

# [0.1.1b2] — 2026-03-30

**Status:** BETA — Independent adversarial hardening pass

## Added

- **ATX-1 coverage completion tests** — promotes T3002, T5001, T10002, T10003 from PARTIAL to COVERED (15 new tests)
- **Security testing report** — `SECURITY_TESTING.md` documenting methodology, results, and accepted risks
- **Machine-readable coverage data** — `data/security-testing.json` consumable for downstream sites
- **Data manifest** — `data/manifest.json` for cross-repo data discovery
- **Coverage export** — `CoverageTracker.to_dict()` and `scripts/generate_coverage_data.py`

## Security Hardening (BT-AUDIT-001 through BT-AUDIT-008)

- **BT-AUDIT-001**: Shell redirect detection — added `<` and `>` to metachar pattern
- **BT-AUDIT-002**: Immutable sensitive path patterns — gateway `list` converted to `tuple`
- **BT-AUDIT-003**: TOCTOU prevention — freeze checks moved inside locks
  (7 methods across capability_registry + policy_engine)
- **BT-AUDIT-004**: Timing-safe seal tokens — `hmac.compare_digest` on both registries
- **BT-AUDIT-005**: Async depth tracking — `async_call` now tracks recursion depth (was missing)
- **BT-AUDIT-006**: Reason sanitization — capability denial no longer leaks agent_id or target
- **BT-AUDIT-007**: Audit resilience — `_row_to_record` handles corrupted JSON gracefully
- **BT-AUDIT-008**: Iterative URL decoding — defeats double/triple percent-encoding evasion

## Stats

- 353 tests, all passing
- ATX-1: 25/25 applicable (100%)
- ATM-1: 6/6 applicable (100%)
- 9 rounds of red/blue team testing across two independent sessions

---

# [0.1.1b1] — 2026-03-30

**Status:** BETA — Security-hardened reference implementation

## Added

### Security Test Suite

- ✅ **Red/Blue Team Framework** — 8 rounds of adversarial testing grounded in ATM-1/ATX-1
  - 353 security tests across 8 test files
  - 29/29 applicable ATX-1 techniques covered (100%)
  - 6/7 ATM-1 attack vectors exercised (AV-6 N/A at engine layer)
  - 5/5 security properties validated
  - ATX-1 coverage tracker with per-technique traceability
  - Findings tracker with ATM-1/ATX-1 mapping and round-by-round changelog

### Risk Engine (Stage 3 — Proportionality Gate)

- ✅ **5-dimension risk scoring** (0.0-10.0 scale, AGP-1 aligned)
  - Capability sensitivity (RFC-0003 risk tiers)
  - Action severity (SHELL_EXEC=9.0 down to FILE_READ=2.0)
  - Target sensitivity (pattern matching with normalization)
  - Historical attempt rate (from audit trail)
  - Behavioral anomaly (sensitivity shift, fixation, trajectory, denial rate)
- ✅ **Proportionality gate** — APPROVED decisions overridden to REQUIRE_CONFIRMATION (>=7.0) or ESCALATE (>=9.0)
- ✅ **Asymmetric amplifier** — fires when EITHER action OR target severity >= 7.0
- ✅ **AGP-1 response fields** — risk_score, risk_category, risk_breakdown in AGPResponse

## Security Hardening (27 fixes)

### Gateway (BT-001 through BT-010)

- Path traversal prevention via posixpath.normpath
- Request replay detection (bounded deque, 10K window)
- Parameter size validation (1MB max)
- Shell metacharacter detection (`;|&\`$()<>`, newlines)
- Sensitive path registry for auto-execution and agent instruction files
- Path normalization in sensitive path matching

### Decision Engine (BT-005, BT-011)

- Unified evaluation lock across all 3 pipeline stages (TOCTOU prevention)
- Independent structural validation (defense-in-depth)
- Thread-safe metrics recording

### Capability Registry & Policy Engine (BT-012, C-2)

- freeze()/unseal() governance state locking with seal tokens
- hmac.compare_digest for constant-time token comparison
- Freeze check inside lock (TOCTOU prevention)
- Registry capacity limit (10K capabilities)

### Risk Engine (BT-014 through BT-023)

- NFKC Unicode normalization for target sensitivity
- URL decoding before pattern matching
- Command prefix stripping (sudo, nohup, env, etc.)
- Fail-closed defaults for unknown tiers/action types (9.0)
- Target sensitivity shift detection (baseline poisoning defense)
- Normalized fixation counting (dilution defense)
- Severity trajectory detection (gradual escalation defense)
- Explanation sanitization (40-char truncation, allowlist)
- Immutable configuration (MappingProxyType, frozen tuples, read-only properties)

### Tool Proxy (BT-006, BT-008, M-5 through M-7)

- Recursion depth limit (max_call_depth=32, sync + async)
- Thread-safe depth counter
- Execution failure audit recording
- O(1) bounded history via deque

### Protocol & Audit (M-2, H-5, M-4, L-4, L-6)

- from_json size limits (10MB) and error wrapping
- Atomic batch_record with BEGIN/COMMIT/ROLLBACK
- WAL checkpoint every 1000 writes
- Bounded session history queries (default 1000)
- AuditSystem.close() public method

### Code Quality

- Full PEP 8 compliance (ruff clean)
- mypy strict: 0 errors
- Registered pytest markers for ATM-1/ATX-1 traceability

## Deferred to v0.2.0

- Agent identity authentication (RFC-0002 transport layer)
- Audit hash chaining / cryptographic integrity (RT-009)
- Parameter semantic analysis (NLP/policy DSL)
- Policy condition sandboxing
- Persistent replay detection
- Supply chain hardening (AV-6)

---

# [Unreleased]

## Planned for v0.2.0 (Q2 2026 — Stage 2)

### Reference Implementation

- 📅 **Governance Gateway Enhancement**
  - Support for multiple transport protocols (HTTP, gRPC, WebSocket)
  - Request rate limiting and throttling
  - Batch action evaluation support
  - Connection pooling and load balancing

- 📅 **Decision Engine Expansion**
  - Context-aware policy evaluation with rich decision context
  - Constraint enforcement and parameter modification
  - Decision caching with policy version tracking
  - Explain functionality for all decisions

- 📅 **Policy Engine Features**
  - YAML policy DSL improvements based on RFC-0003
  - Conditional policy logic (if/then/else)
  - Dynamic policy loading from remote sources
  - Policy testing and validation framework

- 📅 **Audit System Enhancements**
  - Distributed audit trail support
  - Multiple storage backends (PostgreSQL, MongoDB, S3)
  - Long-term retention and archival
  - Compliance reporting (SOC 2, ISO 27001, PCI-DSS)

- 📅 **Tool Proxy Enhancements**
  - Support for additional tool types (REST APIs, GraphQL, gRPC)
  - Tool response interception and validation
  - Rate limiting per tool
  - Fallback and retry logic

- 📅 **Performance Optimization**
  - <15ms P95 governance latency target
  - Capability registry caching strategies
  - Policy evaluation optimization
  - Horizontal scaling patterns and clustering

- 📅 **Testing & Quality**
  - Comprehensive integration test suite
  - Performance benchmarking tools
  - Chaos engineering for resilience testing
  - Security test cases for threat model validation

## Planned for v0.3.0+ (Q3+ 2026 → Stage 5)

- 📅 Federation networking
- 📅 Multi-tenancy support
- 📅 Advanced policy composition
- 📅 Telemetry and observability
- 📅 Kubernetes native support

---

# [0.1.0] — 2026-03-05

**Status:** ✅ **DRAFT SPECIFICATION PHASE**

The AEGIS Runtime v0.1.0 defines the **reference architecture and design** for governance runtime
implementation. This version establishes the runtime **specification** and **design patterns**.
Full production-ready reference implementation is planned for v0.2.0 (Q2 2026).

## Added

### Core Runtime Components

- ✅ **Governance Gateway** — Entry point component specification
  - Request validation and protocol parsing
  - Actor authentication via AGP-1
  - Request routing to Decision Engine
  - Response formatting and transmission
  - Design patterns and implementation guidance

- ✅ **Decision Engine** — Policy evaluation core specification
  - Capability authorization decision algorithm
  - Policy evaluation sequence and logic
  - Risk scoring and context evaluation
  - Decision type implementation (ALLOW, DENY, ESCALATE, REQUIRE_CONFIRMATION)
  - Design patterns with state diagrams

- ✅ **Capability Registry** — Capability definition and storage specification
  - Capability data structure and schema
  - Classification and risk rating system
  - Lookup and retrieval algorithms
  - Constraint specification and validation
  - Implementation patterns

- ✅ **Policy Engine** — Policy evaluation and rule processing specification
  - Policy data model and structure
  - Policy evaluation algorithm
  - Condition matching and logic
  - Decision reason generation
  - Implementation guidance with examples

- ✅ **Tool Proxy Layer** — Controlled execution interface specification
  - Tool invocation interception patterns
  - Request validation and sanitization
  - Execution gating based on governance decision
  - Response recording and audit trail
  - Error handling and fallback logic

- ✅ **Audit Logging System** — Immutable decision and event recording specification
  - Audit entry data structure
  - Storage requirements (immutability, replay-ability)
  - Query interface for forensic analysis
  - Compliance reporting capabilities
  - Long-term retention strategies

### Protocol & Communication

- ✅ **AEGIS Governance Protocol (AGP-1) Implementation**
  - ACTION_PROPOSE message structure and validation
  - ACTION_DECIDE message format and decision reasons
  - ACTION_EXECUTE message and execution tracking
  - ACTION_ESCALATE message for human escalation
  - Error handling and timeout specifications

- ✅ **Schema Definitions**
  - TBD: AGP message schemas (JSON Schema)
  - TBD: Capability schemas
  - TBD: Event schemas
  - Example payloads for development and testing

### Reference Implementation (Design & Patterns)

- ✅ **Architecture Documentation**
  - Runtime component interaction diagrams
  - State machines for governance flow
  - Performance characteristics and targets
  - Scalability and deployment patterns
  - Security architecture and trust boundaries

- ✅ **Implementation Patterns**
  - Governance Gateway patterns (sync, async, streaming)
  - Decision Engine evaluation algorithm pseudocode
  - Policy Engine matching and evaluation logic
  - Audit Trail storage patterns (relational, document, append-only)
  - Tool Proxy interception patterns

- ✅ **Integration Examples** (4 frameworks)
  - LangChain: Tool wrapper pattern with AGP integration
  - CrewAI: Agent governance pattern in multi-agent systems
  - AutoGPT: Command governance with capability registry
  - OpenAI Assistants: Function calling governance pattern

- ✅ **Deployment Guidance**
  - Embedded deployment (<5ms latency target)
  - Sidecar deployment (5-10ms latency target)
  - Central HA deployment (10-15ms latency target)
  - Performance optimization strategies

### Testing & Validation

- ✅ **Test Case Specifications**
  - Happy path (approval) workflow
  - Denial path (rejected action) workflow
  - Escalation path (human decision) workflow
  - Error handling and edge cases
  - Concurrency and race condition handling

- ✅ **Performance Benchmarks** (Targets documented)
  - Governance latency targets per architecture
  - Throughput targets (1K-50K actions/sec)
  - Scaling characteristics and limits
  - Optimization strategies documented

### Documentation

- ✅ **Reference Architecture** (690 lines)
  - Complete runtime design specification
  - Deployment patterns with diagrams
  - Performance considerations
  - Security architecture
  - Integration guidance

- ✅ **Implementation Roadmap**
  - Stage 2 (Q2 2026): Reference implementation
  - Stage 3 (Q3-Q4 2026): Enterprise features
  - Stage 4 (Q1-Q2 2027): Advanced capabilities
  - Stage 5 (Q3 2027-Q4 2028): Federation

## Status

### Implemented (Specification/Documentation)

- ✅ Reference Architecture specification
- ✅ Component design and interaction
- ✅ Protocol integration (AGP-1)
- ✅ Integration patterns (4 frameworks)
- ✅ Deployment guidance
- ✅ Performance targets

### In Progress (v0.2.0 roadmap)

- 🔄 Working reference implementation
- 🔄 Governance Gateway component
- 🔄 Decision Engine with policy evaluation
- 🔄 Capability Registry with persistent storage
- 🔄 Audit logging system
- 🔄 Tool Proxy implementation
- 🔄 Integrated runtime facade
- 🔄 Integration adapters (LangChain, CrewAI, AutoGPT, OpenAI)

### Not Yet Planned

- ⬜ Advanced policy DSL (RFC-0003 pending)
- ⬜ Federation networking
- ⬜ Multi-tenancy support
- ⬜ Advanced caching and performance optimization
- ⬜ Hardware security module (HSM) integration

## Runtime Specification

### Component Versions

| Component | Specification | Status | Target Implementation |
|---|---|---|---|
| Governance Gateway | [Reference Architecture](../aegis-core/architecture/AEGIS_Reference_Architecture.md#governance-gateway) | Design Complete | v0.2.0 |
| Decision Engine | [RFC-0002 (TBD)](../rfc/README.md) | In Progress | v0.2.0 |
| Capability Registry | [RFC-0003 (TBD)](../rfc/README.md) | In Progress | v0.2.0 |
| Policy Engine | [RFC-0003 (TBD)](../rfc/README.md) | In Progress | v0.2.0 |
| Tool Proxy Layer | [Reference Architecture](../aegis-core/architecture/AEGIS_Reference_Architecture.md#tool-proxy-layer) | Design Complete | v0.2.0 |
| Audit System | [Reference Architecture](../aegis-core/architecture/AEGIS_Reference_Architecture.md#audit-system) | Design Complete | v0.2.0 |
| AGP-1 Protocol | [AGP-1 Specification](../aegis-core/protocol/AEGIS_Governance_Protocol_AGP1.md) | Complete | v0.1.0+ |

### Performance Targets

| Component | Target | Notes |
|---|---|---|
| Gateway Validation | <1ms | Request parsing and validation |
| Policy Evaluation | <3ms | Decision Engine policy check |
| Capability Lookup | <1ms | Registry lookup with caching |
| Audit Logging | <1ms | Async audit trail write |
| **Total Latency** | **<15ms P95** | End-to-end governance latency |
| **Throughput** | **1K-50K/sec** | Depends on deployment mode |

### Deployment Targets

| Deployment | Latency | Throughput | Use Cases |
|---|---|---|---|
| **Embedded** | <5ms | 1K+ actions/sec | Agent in-process governance |
| **Sidecar** | 5-10ms | 5K+ actions/sec | Kubernetes/container deployments |
| **Central HA** | 10-15ms | 50K+ actions/sec | Enterprise multi-agent systems |

## Roadmap

See [AEGIS Initiative Roadmap](../aegis-core/roadmap/AEGIS_Roadmap.md) and
[CHANGELOG](../CHANGELOG.md) for overall initiative timeline.

---

# Version Sync

The AEGIS Runtime changelog is synchronized with the main project versions:

- v0.1.0 — Specification and design phase
- v0.2.0 — Reference implementation (Stage 2)
- v1.0.0 — Production-ready runtime (post-community feedback)

For complete project release notes, see [CHANGELOG.md](../CHANGELOG.md).
