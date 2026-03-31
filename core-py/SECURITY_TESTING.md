# AEGIS Core Security Testing Report

**Runtime:** aegis-core v0.1.0
**Date:** 2026-03-30
**Methodology:** Adversarial red/blue team testing across 9 rounds
**Testers:** Two independent AI sessions (Claude Opus 4.6) operating adversarially

---

## Summary

The AEGIS governance runtime underwent 9 rounds of adversarial security testing, conducted by two independent AI sessions operating as competing red and blue teams. One session attacked; the other defended. Then they switched. Each round surfaced new vulnerabilities, which were fixed and re-tested before the next round began.

**Final results:**

| Metric | Value |
|--------|-------|
| Total tests | 353 |
| All passing | Yes |
| Total findings (all rounds) | ~50 |
| Fixed in code | 30+ |
| Deferred (architectural) | 6 |
| Blue team hardening changes | BT-001 through BT-AUDIT-008 |
| Red/blue team rounds | 9 |
| ATX-1 technique coverage | 25/25 applicable (100%) |
| ATM-1 attack vector coverage | 6/6 applicable (100%) |
| ATM-1 security properties | 5/5 covered |
| Source files audited | 11 (every Python file in the runtime) |

---

## What Was Tested

Every Python source file in the AEGIS governance runtime was audited for security vulnerabilities:

| Module | Attack Surface |
|--------|---------------|
| `gateway.py` | Input validation, shell metacharacter detection, sensitive path protection, replay prevention |
| `decision_engine.py` | TOCTOU races, capability/policy/risk pipeline integrity, information leakage |
| `risk.py` | Score evasion, threshold gaming, amplifier bypass, Unicode homoglyph evasion, command prefix evasion, module attribute replacement, private attribute bypass |
| `policy_engine.py` | Freeze/unseal bypass, timing attacks on seal tokens, TOCTOU races, policy condition exploitation |
| `capability_registry.py` | Freeze/unseal bypass, timing attacks, TOCTOU races, wildcard capability abuse |
| `audit.py` | Record tampering, audit injection, availability attacks, corrupted data handling |
| `tool_proxy.py` | Recursive invocation loops, depth tracking bypass (sync and async), execution failure recording |
| `protocol.py` | JSON deserialization limits, payload size enforcement |
| `runtime.py` | Component wiring, lifecycle management |
| `exceptions.py` | Error message information leakage |

---

## ATX-1 Technique Coverage

The [ATX-1 Adversarial Threat Taxonomy](https://doi.org/10.21227/015v-9641) defines 29 techniques across 10 tactics for attacks against AI governance systems. AEGIS Core has test coverage for every technique applicable at the runtime engine layer.

### Fully Covered (25 techniques)

| Tactic | Techniques | Test Count |
|--------|-----------|------------|
| TA001: Violate Authority Boundaries | T1001, T1002, T1003 | 6 |
| TA002: Exceed Operational Scope | T2001, T2002, T2003, T2004 | 8 |
| TA003: Compromise System Integrity | T3001, T3002 | 5 |
| TA005: Violate State Integrity | T5001, T5002, T5003 | 7 |
| TA006: Abuse Resource Allocation | T6001, T6002 | 4 |
| TA007: Manipulate Agent Interactions | T7001, T7002, T7004 | 6 |
| TA008: Establish or Modify Persistence | T8001, T8002 | 12 |
| TA009: Evade Detection or Oversight | T9001, T9002 | 5 |
| TA010: Act Beyond Governance Interpretation | T10001, T10002, T10003, T10004 | 28 |

### Not Applicable at Runtime Layer (4 techniques)

| Technique | Reason | Where It Belongs |
|-----------|--------|-----------------|
| T4001: Exfiltrate Context-Scoped Data | Requires agent-to-external data flows | aegis-labs integration tests |
| T4002: Leak Cross-Session Data | Requires persistent agent memory | aegis-labs integration tests |
| T4003: Cross-Domain Secret Leakage | Requires multi-domain deployment | aegis-platform integration tests |
| T7003: Induce Cross-Agent Behavioral Drift | Requires longitudinal multi-session testing | aegis-labs integration tests |

---

## ATM-1 Attack Vector Coverage

The ATM-1 Threat Matrix defines 7 attack surface categories. AEGIS Core covers all categories applicable at the runtime layer.

| Vector | Description | Status | Tests |
|--------|-------------|--------|-------|
| AV-1 | Protocol-level attacks (replay, injection) | Covered | 4 |
| AV-2 | Policy-layer attacks (evasion, bypass, tampering) | Covered | 12 |
| AV-3 | Identity & authentication attacks | Covered | 5 |
| AV-4 | Audit & logging attacks | Covered | 5 |
| AV-5 | Timing & side-channel attacks | Covered | 2 |
| AV-6 | Supply-chain & dependency attacks | N/A | Deployment layer |
| AV-7 | Distributed & coordinated attacks | Covered | 5 |

---

## Key Hardening Measures

### Input Validation & Sanitization
- Shell metacharacter detection (`; | & \` $ ( ) < >`, newlines)
- Sensitive path write protection (git hooks, shell init, CI/CD, Dockerfiles, agent instruction files)
- Path traversal normalization via `posixpath.normpath`
- Unicode NFKC normalization to defeat homoglyph evasion (Cyrillic, fullwidth, combining characters)
- Iterative URL percent-decoding to defeat double/triple encoding
- Command prefix stripping (`sudo`, `nohup`, `nice`, `timeout`, env var prefixes)
- JSON payload size limits (1 MB parameters, 10 MB protocol messages)
- Agent ID format validation (alphanumeric + hyphens/underscores/dots, max 256 chars)

### Risk Scoring Model
- 5-dimension composite scoring: capability sensitivity, action severity, target sensitivity, historical rate, behavioral anomaly
- Asymmetric amplifier: fires when either action severity or target sensitivity exceeds 7.0
- Fail-closed defaults: unknown action types and capability tiers score 9.0/10.0
- Behavioral anomaly detection: severity trajectory shifts, target sensitivity shifts, fixation detection, denial rate monitoring
- Explanation sanitization: attacker-controlled strings in risk explanations are stripped of HTML, quotes, newlines, and control characters

### Immutability & Tamper Resistance
- `MappingProxyType` for scoring weight tables (prevents dict mutation)
- Immutable tuple for sensitive target patterns
- `__slots__` and custom `__setattr__` on `RiskEngine` (blocks post-init mutation of thresholds and audit reference)
- Freeze/unseal mechanism with UUID seal tokens on `CapabilityRegistry` and `PolicyEngine`
- Constant-time seal token comparison via `hmac.compare_digest` (prevents timing attacks)

### Concurrency Safety
- Unified evaluation lock across capability + policy + risk stages (prevents TOCTOU)
- Freeze checks inside locks on all mutation methods (7 methods fixed across 2 modules)
- Thread-safe metrics collection with dedicated lock
- Thread-safe recursive depth tracking for both sync and async tool invocation
- Bounded replay detection window (10,000 request IDs via `collections.deque`)
- WAL checkpointing on audit database to prevent unbounded growth

### Audit Integrity
- Append-only SQLite audit trail with WAL journal mode
- Every decision recorded regardless of outcome (approved, denied, escalated)
- Tool execution failures recorded separately from governance approvals
- Graceful handling of corrupted audit records (availability over crash)
- Parameterized SQL queries throughout (no SQL injection surface)

---

## Accepted Risks & Deferred Items

These findings are documented, accepted, and tracked for resolution in future versions:

| Finding | Risk | Resolution Path |
|---------|------|----------------|
| `object.__setattr__` bypass | Python C-level slot access bypasses custom `__setattr__` | Rust runtime (true type enforcement) |
| Module attribute replacement | `risk_module.WEIGHTS = {...}` replaces entire scoring table | Process isolation boundary (AEGIS daemon) |
| Seal token memory exposure | `_seal_token` readable via `engine._seal_token` | Rust runtime (private fields) |
| Silent evidence replacement | Corrupted JSON in audit records replaced with `{}` | RT-009 hash chaining (detects tampering) |
| Agent identity spoofing | No transport-layer authentication on `agent_id` | v0.2.0 RFC-0002 (mTLS, bearer tokens) |
| Parameter semantic analysis | Risk engine scores target string, not action parameters | v0.2.0 NLP/policy DSL |

All accepted risks are mitigated by the AEGIS deployment model: the runtime operates inside a process isolation boundary (the AEGIS daemon) where the attack surface for code-level manipulation is constrained by the daemon's own security posture.

---

## Methodology

### Adversarial Structure

Two independent Claude Opus 4.6 sessions operated as competing teams:

1. **Red team** — Attempted to break the runtime by crafting adversarial inputs, exploiting edge cases, manipulating internal state, and finding evasion paths through the governance pipeline.

2. **Blue team** — Fixed every vulnerability found by the red team, then hardened surrounding code preemptively. Fixes were validated by re-running all existing tests plus new tests targeting the specific vulnerability.

3. **Role reversal** — After each round, sessions switched roles. The previous blue team attacked the other session's fixes; the previous red team defended.

This adversarial structure ensures that fixes are tested by a session that did not write the fix, reducing confirmation bias.

### Test Categories

| Category | Purpose | Test Files |
|----------|---------|------------|
| Blue team | Validate fixes for known vulnerabilities | `test_blue_team.py` |
| Red team R1-R2 | Adversarial attacks against gateway, policy, capability, audit | `test_red_team.py`, `test_red_team_r2.py` |
| Risk engine R1-R4 | Adversarial attacks against risk scoring model | `test_red_team_risk.py` through `test_red_team_risk_r4.py` |
| ATX-1 completion | Coverage gap closure for partial techniques | `test_atx1_coverage_completion.py` |
| Functional | Core functionality validation | `test_audit.py`, `test_capability_registry.py`, `test_decision_engine.py`, `test_gateway.py`, `test_integration.py`, `test_policy_engine.py`, `test_protocol.py`, `test_tool_proxy.py` |

### Traceability

Every security test is tagged with ATX-1 technique IDs and ATM-1 attack vectors via pytest markers:

```python
@pytest.mark.atx1(technique_id="T10004")
@pytest.mark.atm1(attack_vector="AV-2")
def test_shell_metacharacter_detection(self, runtime):
    ...
```

Coverage is tracked programmatically in `tests/security/coverage.py`, which maintains the complete ATX-1/ATM-1 taxonomy and can generate coverage reports on demand.

---

## Reproducibility

All tests run in under 2 seconds on commodity hardware:

```
353 passed in 1.40s
```

Zero external dependencies. Zero network calls. Zero mocks of core behavior. The runtime is stdlib-only Python, and the test suite exercises it end-to-end through the public API.

```bash
cd core-py
python -m pytest tests/ -v
```

---

*This report was generated from adversarial testing conducted on 2026-03-30 against aegis-core commit history. The AEGIS governance runtime is developed by the AEGIS Initiative (Finnoybu IP LLC).*
