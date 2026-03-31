"""Red/Blue Team Findings Tracker.

Provides structured recording and reporting of security findings
discovered during adversarial testing, mapped to ATM-1/ATX-1.

Usage:
    tracker = FindingsTracker()
    tracker.add_finding(Finding(
        id="RT-001",
        title="Direct DecisionEngine bypass",
        severity=Severity.HIGH,
        atm1_refs=["AV-2"],
        atx1_refs=["T1001"],
        sp_violated=["SP-4"],
        description="DecisionEngine.evaluate() can be called directly...",
        reproduction="engine._evaluate(request)  # bypasses gateway validation",
        status=Status.OPEN,
    ))
    tracker.add_fix(Fix(
        finding_id="RT-001",
        round_number=1,
        description="Added internal-only guard to DecisionEngine",
        commit_ref="abc1234",
    ))
    print(tracker.generate_report())
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Status(str, Enum):
    OPEN = "OPEN"
    FIXED = "FIXED"
    WONTFIX = "WONTFIX"
    MITIGATED = "MITIGATED"


@dataclass
class Finding:
    """A single red team finding."""

    id: str
    title: str
    severity: Severity
    atm1_refs: list[str]
    atx1_refs: list[str]
    sp_violated: list[str]
    description: str
    reproduction: str
    status: Status = Status.OPEN
    round_discovered: int = 1
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass
class Fix:
    """A blue team fix for a finding."""

    finding_id: str
    round_number: int
    description: str
    commit_ref: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class FindingsTracker:
    """Tracks findings and fixes across red/blue team rounds."""

    def __init__(self) -> None:
        self._findings: dict[str, Finding] = {}
        self._fixes: list[Fix] = []
        self._current_round: int = 1

    @property
    def current_round(self) -> int:
        return self._current_round

    def advance_round(self) -> int:
        """Move to the next red/blue team round."""
        self._current_round += 1
        return self._current_round

    def add_finding(self, finding: Finding) -> None:
        self._findings[finding.id] = finding

    def add_fix(self, fix: Fix) -> None:
        self._fixes.append(fix)
        if fix.finding_id in self._findings:
            self._findings[fix.finding_id].status = Status.FIXED

    def open_findings(self) -> list[Finding]:
        return [f for f in self._findings.values() if f.status == Status.OPEN]

    def fixed_findings(self) -> list[Finding]:
        return [f for f in self._findings.values() if f.status == Status.FIXED]

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self._findings.values() if f.severity == severity]

    def generate_report(self) -> str:
        """Generate a markdown report of all findings and fixes."""
        lines = [
            "# AEGIS Red/Blue Team Security Report",
            "",
            f"**Round:** {self._current_round}",
            f"**Total Findings:** {len(self._findings)}",
            f"**Open:** {len(self.open_findings())}",
            f"**Fixed:** {len(self.fixed_findings())}",
            "",
        ]

        # Summary by severity
        lines.append("## Summary by Severity")
        lines.append("")
        lines.append("| Severity | Count | Open | Fixed |")
        lines.append("|----------|-------|------|-------|")
        for sev in Severity:
            by_sev = self.findings_by_severity(sev)
            open_count = sum(1 for f in by_sev if f.status == Status.OPEN)
            fixed_count = sum(1 for f in by_sev if f.status == Status.FIXED)
            if by_sev:
                lines.append(f"| {sev.value} | {len(by_sev)} | {open_count} | {fixed_count} |")
        lines.append("")

        # Detailed findings
        lines.append("## Findings")
        lines.append("")
        for finding in sorted(self._findings.values(), key=lambda f: f.id):
            status_icon = {
                Status.OPEN: "🔴",
                Status.FIXED: "🟢",
                Status.WONTFIX: "⚪",
                Status.MITIGATED: "🟡",
            }.get(finding.status, "❓")
            lines.append(f"### {status_icon} {finding.id}: {finding.title}")
            lines.append("")
            lines.append(f"- **Severity:** {finding.severity.value}")
            lines.append(f"- **Status:** {finding.status.value}")
            lines.append(f"- **ATM-1:** {', '.join(finding.atm1_refs)}")
            lines.append(f"- **ATX-1:** {', '.join(finding.atx1_refs)}")
            lines.append(f"- **Security Properties Violated:** {', '.join(finding.sp_violated)}")
            lines.append(f"- **Round Discovered:** {finding.round_discovered}")
            lines.append("")
            lines.append(f"**Description:** {finding.description}")
            lines.append("")
            lines.append("**Reproduction:**")
            lines.append(f"```python\n{finding.reproduction}\n```")
            lines.append("")

            # Append fixes for this finding
            fixes = [f for f in self._fixes if f.finding_id == finding.id]
            if fixes:
                lines.append("**Fixes Applied:**")
                for fix in fixes:
                    lines.append(f"- Round {fix.round_number}: {fix.description}")
                lines.append("")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Pre-populated findings from Round 1 red team analysis
# ---------------------------------------------------------------------------

ROUND_1_FINDINGS: list[Finding] = [
    Finding(
        id="RT-001",
        title="Gateway bypass via direct DecisionEngine access",
        severity=Severity.HIGH,
        atm1_refs=["AV-2"],
        atx1_refs=["T1001", "T9001"],
        sp_violated=["SP-1", "SP-4"],
        description=(
            "DecisionEngine.evaluate() is a public method that can be called "
            "directly, bypassing all GovernanceGateway validation. An agent "
            "with a reference to the engine can submit unvalidated requests."
        ),
        reproduction=(
            "engine = runtime._decision_engine\n"
            "# Bypass gateway — no validation on agent_id, action, context\n"
            "response = engine._evaluate(malformed_request)"
        ),
    ),
    Finding(
        id="RT-002",
        title="Path traversal in capability target patterns",
        severity=Severity.HIGH,
        atm1_refs=["AV-2"],
        atx1_refs=["T2001", "T10001"],
        sp_violated=["SP-4"],
        description=(
            "Capability target_patterns use fnmatch globs without path "
            "normalization. A target like '/docs/../etc/passwd' matches "
            "a pattern '/docs/*' because fnmatch does not resolve '..'."
        ),
        reproduction=(
            "cap = Capability(target_patterns=['/docs/*'], ...)\n"
            "# This returns True — path traversal succeeds\n"
            "cap.covers('file_read', '/docs/../etc/passwd')"
        ),
    ),
    Finding(
        id="RT-003",
        title="TOCTOU race between capability check and policy evaluation",
        severity=Severity.MEDIUM,
        atm1_refs=["AV-5"],
        atx1_refs=["T2001"],
        sp_violated=["SP-1", "SP-3"],
        description=(
            "DecisionEngine.evaluate() checks capabilities then evaluates "
            "policies in two separate steps without holding a unified lock. "
            "A capability could be revoked between the two checks."
        ),
        reproduction=(
            "# Thread 1: engine._evaluate(request) — passes capability check\n"
            "# Thread 2: registry.revoke(agent_id, cap_id) — revokes mid-eval\n"
            "# Thread 1: continues to policy eval with revoked capability"
        ),
    ),
    Finding(
        id="RT-004",
        title="Policy condition exceptions silently swallowed in find_matching_policies",
        severity=Severity.MEDIUM,
        atm1_refs=["AV-2"],
        atx1_refs=["T9002"],
        sp_violated=["SP-1"],
        description=(
            "PolicyEngine.find_matching_policies() catches all exceptions "
            "from policy conditions and silently ignores them (line 314-315), "
            "while evaluate() raises AEGISPolicyError. This inconsistency "
            "allows a malicious condition to hide its failure from detection."
        ),
        reproduction=(
            "def evil_condition(req):\n"
            "    raise RuntimeError('oops')\n"
            "# find_matching_policies: silently skips\n"
            "# evaluate: raises AEGISPolicyError\n"
            "# Inconsistent behavior = detection evasion"
        ),
    ),
    Finding(
        id="RT-005",
        title="No request_id replay protection",
        severity=Severity.MEDIUM,
        atm1_refs=["AV-1"],
        atx1_refs=["T1002"],
        sp_violated=["SP-1", "SP-2"],
        description=(
            "The same request_id can be submitted multiple times. The audit "
            "system records each submission as a separate entry. There is no "
            "replay detection or deduplication."
        ),
        reproduction=(
            "request = make_request()\n"
            "# Submit the exact same request twice\n"
            "r1 = gateway.submit(request)\n"
            "r2 = gateway.submit(request)  # succeeds, no replay detection"
        ),
    ),
    Finding(
        id="RT-006",
        title="Capability grant has no authorization check",
        severity=Severity.HIGH,
        atm1_refs=["AV-3"],
        atx1_refs=["T1001", "T8002"],
        sp_violated=["SP-4"],
        description=(
            "CapabilityRegistry.grant() performs no authorization check. "
            "Any caller with a reference to the registry can grant any "
            "capability to any agent, including themselves."
        ),
        reproduction=(
            "# An agent with registry access can self-escalate\n"
            "registry.grant('malicious-agent', 'cap-admin')"
        ),
    ),
    Finding(
        id="RT-007",
        title="Policy removal during live evaluation window",
        severity=Severity.MEDIUM,
        atm1_refs=["AV-5"],
        atx1_refs=["T8002"],
        sp_violated=["SP-3"],
        description=(
            "PolicyEngine.evaluate() acquires the lock only to snapshot "
            "the sorted policy list, then releases it. A concurrent "
            "remove_policy() call could alter the policy set while "
            "evaluation is still iterating."
        ),
        reproduction=(
            "# Thread 1: engine._evaluate() — snapshots policies, releases lock\n"
            "# Thread 2: engine.remove_policy('critical-deny') — removes deny\n"
            "# Thread 1: continues eval without the deny policy"
        ),
    ),
    Finding(
        id="RT-008",
        title="No parameter size limits enables memory exhaustion",
        severity=Severity.LOW,
        atm1_refs=["AV-1"],
        atx1_refs=["T6002"],
        sp_violated=[],
        description=(
            "AGPRequest.action.parameters has no size limit. An agent "
            "can submit arbitrarily large parameter dicts, potentially "
            "causing memory exhaustion in the gateway/engine."
        ),
        reproduction=(
            "huge_params = {'data': 'x' * (100 * 1024 * 1024)}  # 100MB\n"
            "request = make_request(parameters=huge_params)\n"
            "gateway.submit(request)  # no size check"
        ),
    ),
    Finding(
        id="RT-009",
        title="Audit records not integrity-protected (confirms T9002)",
        severity=Severity.LOW,
        atm1_refs=["AV-4"],
        atx1_refs=["T9002"],
        sp_violated=["SP-5"],
        description=(
            "Audit records use datetime.now() timestamps with no hash "
            "chaining or cryptographic signing. A process with DB access "
            "could modify or delete audit records without detection. "
            "Batch timestamp collision (identical timestamps across batch "
            "records) is an implementation defect confirming T9002, not a "
            "new subtechnique per MITRE methodology — the behavioral "
            "pattern (obfuscate traceability) is already captured."
        ),
        reproduction=(
            "# Direct SQLite access bypasses the AuditSystem API\n"
            "conn = sqlite3.connect(db_path)\n"
            "conn.execute('UPDATE audit_records SET decision=\"approved\" WHERE id=?', (id,))"
        ),
    ),
    Finding(
        id="RT-010",
        title="Policy priority manipulation enables allow-before-deny",
        severity=Severity.HIGH,
        atm1_refs=["AV-2"],
        atx1_refs=["T8002"],
        sp_violated=["SP-1"],
        description=(
            "Policy evaluation checks deny policies by matching effect, "
            "not by priority order alone. However, if an attacker adds an "
            "ALLOW policy at priority 0 and no DENY policy matches, the "
            "action is approved. The lack of policy registration authorization "
            "compounds this with RT-006."
        ),
        reproduction=(
            "# Attacker adds a catch-all allow at highest priority\n"
            "engine.add_policy(Policy(\n"
            "    id='backdoor', effect=PolicyEffect.ALLOW,\n"
            "    priority=0, conditions=[],\n"
            "))"
        ),
    ),
]
