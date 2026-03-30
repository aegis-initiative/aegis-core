# Red/Blue Team Security Testing Change Log

All changes are mapped to ATM-1 attack vectors (STRIDE-based), ATX-1
techniques (MITRE methodology), and AEGIS security properties (SP-1..SP-5).

ATX-1 follows MITRE ATT&CK methodology and is positioned as the third
column: ATT&CK (human→systems), ATLAS (human→AI), **ATX-1 / MITRE AEGIS**
(AI agent→systems/users/agents).

---

## Round 3 — Tier 1 + Tier 2 Blue Team Fixes

### Blue Team Changes

| Change | File | ATM-1 | ATX-1 | Finding | Description |
|--------|------|-------|-------|---------|-------------|
| BT-006 | `tool_proxy.py` | AV-1 | T6001 | RT-017 | Added `max_call_depth` (default 32) to ToolProxy. Raises `RecursionError` when depth exceeded. Prevents recursive invocation loops. |
| BT-007 | `capability_registry.py` | AV-2 | — | RT-024 | Skip `posixpath.normpath` for URI-scheme targets (`://`). Fixes side effect of BT-001 that collapsed `://` to `:/`. |
| BT-008 | `tool_proxy.py`, `runtime.py` | AV-4 | T5003 | RT-016 | ToolProxy now records `execution_failed` audit entry when a tool raises after governance approval. AEGISRuntime passes audit system to ToolProxy. |
| BT-009 | `gateway.py` | AV-2 | T10004 | RT-021 | Gateway rejects SHELL_EXEC targets containing shell metacharacters (`;`, `|`, `&`, `` ` ``, `$()`, `\n`). Prevents parser divergence between governance and runtime. |
| BT-010 | `gateway.py` | AV-2 | T10002, T10003 | RT-022, RT-023 | Sensitive path registry in gateway. FILE_WRITE to auto-execution paths (git hooks, shell init, CI/CD, package managers) and agent instruction files (CLAUDE.md, .cursorrules, etc.) are rejected. |

### Updated Finding Status

| ID | Previous Status | New Status | Fix |
|----|----------------|------------|-----|
| RT-016 | OPEN | FIXED (BT-008) | Execution failures now audited |
| RT-017 | OPEN | FIXED (BT-006) | Recursion depth limit enforced |
| RT-021 | OPEN | FIXED (BT-009) | Shell metacharacter detection |
| RT-022 | OPEN | FIXED (BT-010) | Auto-exec path protection |
| RT-023 | OPEN | FIXED (BT-010) | Instruction file protection |
| RT-024 | OPEN | FIXED (BT-007) | URI scheme handling fixed |

---

## Round 2 — Expanded Coverage + Blue Team Fixes

### Blue Team Changes (Fixes for Round 1 Findings)

| Change | File | ATM-1 | ATX-1 | Finding | Description |
|--------|------|-------|-------|---------|-------------|
| BT-001 | `capability_registry.py` | AV-2 | T10001 | RT-002 | Added `posixpath.normpath()` to `Capability.covers()` to prevent path traversal via `..` sequences. |
| BT-002 | `policy_engine.py` | AV-2 | T9002 | RT-004 | `find_matching_policies()` now raises `AEGISPolicyError` consistently with `evaluate()`. |
| BT-003 | `gateway.py` | AV-1 | T1002 | RT-005 | Replay detection via bounded deque (10,000 window). |
| BT-004 | `gateway.py` | AV-1 | T6002 | RT-008 | Parameter size validation (1 MB max). |
| BT-005 | `decision_engine.py` | AV-5 | T2001, T8002 | RT-003, RT-007 | Unified `_eval_lock` across capability check and policy evaluation. |

### Round 2 Red Team Findings

| ID | Title | Severity | ATM-1 | ATX-1 | SP | Status |
|----|-------|----------|-------|-------|----|--------|
| RT-011 | No distribution/rate controls for mass actions | HIGH | AV-7 | T1003 | — | OPEN (v0.2.0) |
| RT-012 | No aggregate impact assessment for bulk operations | HIGH | AV-2 | T2002 | — | OPEN (v0.2.0) |
| RT-013 | Cross-agent delegation composes to exfiltration | HIGH | AV-2 | T2003 | — | OPEN (v0.2.0) |
| RT-014 | No proportionality gate for destructive actions | CRITICAL | AV-2 | T3001 | SP-1 | OPEN (v0.2.0) |
| RT-015 | Agent identity spoofing (no authentication) | HIGH | AV-3 | T5002 | SP-2 | OPEN (v0.2.0) |
| RT-016 | Tool execution failures not recorded in audit | MEDIUM | AV-4 | T5003 | SP-5 | FIXED (BT-008) |
| RT-017 | No recursion depth limit in tool proxy | MEDIUM | AV-1 | T6001 | — | FIXED (BT-006) |
| RT-018 | Delegation chain privilege escalation | HIGH | AV-3 | T7002 | SP-4 | OPEN (v0.2.0) |
| RT-019 | No anomalous convergence detection | MEDIUM | AV-7 | T7004 | — | OPEN (v0.2.0) |
| RT-020 | Malicious parameters stored verbatim in audit | LOW | AV-4 | T8001 | SP-5 | OPEN |
| RT-021 | Shell metacharacters bypass governance | HIGH | AV-2 | T10004 | SP-1 | FIXED (BT-009) |
| RT-022 | Auto-execution paths not protected | HIGH | AV-2 | T10002 | — | FIXED (BT-010) |
| RT-023 | Agent instruction files not protected | CRITICAL | AV-2 | T10003 | — | FIXED (BT-010) |
| RT-024 | BT-001 side effect: normpath collapses URI schemes | MEDIUM | AV-2 | — | SP-4 | FIXED (BT-007) |

### Reclassifications

| Original ID | Original Proposal | Reclassified As | Rationale |
|-------------|-------------------|-----------------|-----------|
| ND-001 | New subtechnique of T9002 | T9002 confirmation | Per MITRE methodology: implementation defect, not distinct behavioral pattern. |

### Techniques Triaged as Not Testable at Engine Layer

| ATX-1 | Technique | Required Testing Layer |
|-------|-----------|----------------------|
| T4001 | Exfiltrate Context-Scoped Data | Agent integration |
| T4002 | Leak Cross-Session Data | Agent integration |
| T4003 | Cross-Domain Secret Leakage | Multi-domain deployment |
| T7003 | Induce Cross-Agent Behavioral Drift | Agent longitudinal |

---

## Round 1 — Initial Assessment

### Red Team Findings

| ID | Title | Severity | ATM-1 | ATX-1 | SP | Status |
|----|-------|----------|-------|-------|----|--------|
| RT-001 | Gateway bypass via direct DecisionEngine access | HIGH | AV-2 | T1001, T9001 | SP-1, SP-4 | OPEN (architectural) |
| RT-002 | Path traversal in capability target patterns | HIGH | AV-2 | T2001, T10001 | SP-4 | FIXED (BT-001) |
| RT-003 | TOCTOU race: capability check / policy eval | MEDIUM | AV-5 | T2001 | SP-1, SP-3 | FIXED (BT-005) |
| RT-004 | Policy condition exceptions silently swallowed | MEDIUM | AV-2 | T9002 | SP-1 | FIXED (BT-002) |
| RT-005 | No request_id replay protection | MEDIUM | AV-1 | T1002 | SP-1, SP-2 | FIXED (BT-003) |
| RT-006 | Capability grant has no authorization check | HIGH | AV-3 | T1001, T8002 | SP-4 | OPEN (architectural) |
| RT-007 | Policy removal during live evaluation | MEDIUM | AV-5 | T8002 | SP-3 | FIXED (BT-005) |
| RT-008 | No parameter size limits | LOW | AV-1 | T6002 | — | FIXED (BT-004) |
| RT-009 | Audit records not integrity-protected | LOW | AV-4 | T9002 | SP-5 | OPEN (v0.2.0) |
| RT-010 | Policy priority manipulation (no auth on add) | HIGH | AV-2 | T8002 | SP-1 | OPEN (architectural) |

---

## Cumulative Status

| Metric | Count |
|--------|-------|
| Total findings | 24 |
| Fixed | 12 |
| Open (v0.2.0 roadmap) | 8 |
| Open (architectural) | 3 |
| Open (low priority) | 1 |
| Blue team changes | 10 |
| ATX-1 techniques covered | 25/29 (86%) |
| ATM-1 attack vectors covered | 6/7 (AV-6 N/A) |
| Security properties covered | 5/5 |
| Test count | 68 security + 187 existing = 255 total |
