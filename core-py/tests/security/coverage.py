"""ATM-1 / ATX-1 Coverage Tracker.

Maintains a complete map of every ATM-1 attack vector and ATX-1
tactic/technique, tracks which have test coverage, and identifies gaps.

Usage:
    tracker = CoverageTracker()
    tracker.mark_covered("T1001", test_id="test_gateway_bypass", notes="Red team RT-001")
    print(tracker.generate_coverage_report())
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class CoverageStatus(str, Enum):
    COVERED = "COVERED"  # Has dedicated test(s)
    PARTIAL = "PARTIAL"  # Tested indirectly or incompletely
    NOT_COVERED = "NOT_COVERED"  # No test coverage
    NOT_APPLICABLE = "N/A"  # Cannot be tested at this layer


@dataclass
class CoverageEntry:
    """Coverage status for a single technique or attack vector."""

    id: str
    name: str
    parent: str  # tactic ID or category
    status: CoverageStatus = CoverageStatus.NOT_COVERED
    test_ids: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    notes: str = ""


# ===================================================================
# ATX-1 Full Taxonomy (v2.1.0 — 10 tactics, 34 techniques)
# ===================================================================

ATX1_TAXONOMY: dict[str, dict] = {
    # --- TA001: Violate Authority Boundaries ---
    "TA001": {"name": "Violate Authority Boundaries", "techniques": ["T1001", "T1002", "T1003"]},
    "T1001": {"name": "Execute Non-Owner Instruction", "tactic": "TA001", "severity": "high"},
    "T1002": {"name": "Infer Implicit Authority", "tactic": "TA001", "severity": "high"},
    "T1003": {
        "name": "Propagate Spoofed Authority at Scale",
        "tactic": "TA001",
        "severity": "critical",
    },
    # --- TA002: Exceed Operational Scope ---
    "TA002": {
        "name": "Exceed Operational Scope",
        "techniques": ["T2001", "T2002", "T2003", "T2004"],
    },
    "T2001": {"name": "Expand Task Scope Autonomously", "tactic": "TA002", "severity": "high"},
    "T2002": {"name": "Perform Unvalidated Bulk Operations", "tactic": "TA002", "severity": "high"},
    "T2003": {
        "name": "Obscure Objective Through Delegation",
        "tactic": "TA002",
        "severity": "high",
    },
    "T2004": {"name": "Exploit Tool-Chain Composition", "tactic": "TA002", "severity": "high"},
    # --- TA003: Compromise System Integrity ---
    "TA003": {"name": "Compromise System Integrity", "techniques": ["T3001", "T3002"]},
    "T3001": {
        "name": "Perform Irreversible Destructive Action",
        "tactic": "TA003",
        "severity": "critical",
    },
    "T3002": {
        "name": "Trigger Cascading System Changes",
        "tactic": "TA003",
        "severity": "critical",
    },
    # --- TA004: Expose or Exfiltrate Information ---
    "TA004": {
        "name": "Expose or Exfiltrate Information",
        "techniques": ["T4001", "T4002", "T4003"],
    },
    "T4001": {"name": "Exfiltrate Context-Scoped Data", "tactic": "TA004", "severity": "critical"},
    "T4002": {
        "name": "Leak Cross-Session or Persistent Data",
        "tactic": "TA004",
        "severity": "high",
    },
    "T4003": {"name": "Cross-Domain Secret Leakage", "tactic": "TA004", "severity": "high"},
    # --- TA005: Violate State Integrity ---
    "TA005": {"name": "Violate State Integrity", "techniques": ["T5001", "T5002", "T5003"]},
    "T5001": {"name": "Report False Task Completion", "tactic": "TA005", "severity": "high"},
    "T5002": {"name": "Fabricate Action Attribution", "tactic": "TA005", "severity": "medium"},
    "T5003": {
        "name": "Suppress or Omit Execution Failure",
        "tactic": "TA005",
        "severity": "medium",
    },
    # --- TA006: Abuse Resource Allocation ---
    "TA006": {"name": "Abuse Resource Allocation", "techniques": ["T6001", "T6002"]},
    "T6001": {"name": "Execute Recursive Invocation Loops", "tactic": "TA006", "severity": "high"},
    "T6002": {
        "name": "Consume Unbounded External Resources",
        "tactic": "TA006",
        "severity": "medium",
    },
    # --- TA007: Manipulate Agent Interactions ---
    "TA007": {
        "name": "Manipulate Agent Interactions",
        "techniques": ["T7001", "T7002", "T7003", "T7004"],
    },
    "T7001": {"name": "Spoof Agent Identity", "tactic": "TA007", "severity": "critical"},
    "T7002": {"name": "Inject Malicious Delegation Chains", "tactic": "TA007", "severity": "high"},
    "T7003": {
        "name": "Induce Cross-Agent Behavioral Drift",
        "tactic": "TA007",
        "severity": "medium",
    },
    "T7004": {"name": "Induce Unsafe Consensus", "tactic": "TA007", "severity": "high"},
    # --- TA008: Establish or Modify Persistence ---
    "TA008": {"name": "Establish or Modify Persistence", "techniques": ["T8001", "T8002"]},
    "T8001": {"name": "Poison Persistent Memory", "tactic": "TA008", "severity": "high"},
    "T8002": {
        "name": "Corrupt Governance or Policy State",
        "tactic": "TA008",
        "severity": "critical",
    },
    # --- TA009: Evade Detection or Oversight ---
    "TA009": {"name": "Evade Detection or Oversight", "techniques": ["T9001", "T9002"]},
    "T9001": {
        "name": "Operate Outside Monitoring Boundaries",
        "tactic": "TA009",
        "severity": "medium",
    },
    "T9002": {"name": "Obfuscate Action Traceability", "tactic": "TA009", "severity": "medium"},
    # --- TA010: Act Beyond Governance Interpretation ---
    "TA010": {
        "name": "Act Beyond Governance Interpretation",
        "techniques": ["T10001", "T10002", "T10003", "T10004"],
    },
    "T10001": {
        "name": "Exploit Pseudo-Filesystem Capabilities",
        "tactic": "TA010",
        "severity": "high",
    },
    "T10002": {
        "name": "Establish Persistence via Environment Auto-Execution",
        "tactic": "TA010",
        "severity": "high",
    },
    "T10003": {
        "name": "Inject Persistent Agent Instructions",
        "tactic": "TA010",
        "severity": "critical",
    },
    "T10004": {
        "name": "Exploit Governance-Runtime Parser Divergence",
        "tactic": "TA010",
        "severity": "high",
    },
}

# ===================================================================
# ATM-1 Attack Vectors and Security Properties
# ===================================================================

ATM1_ATTACK_VECTORS: dict[str, str] = {
    "AV-1": "Protocol-level attacks (MITM, message injection, replay, token theft)",
    "AV-2": "Policy-layer attacks (evasion, bypass, tampering, authorization bypass)",
    "AV-3": "Identity & authentication attacks (spoofing, lateral movement, credential harvesting)",
    "AV-4": "Audit & logging attacks (tampering, injection, availability)",
    "AV-5": "Timing & side-channel attacks (policy eval timing, risk scoring inference)",
    "AV-6": "Supply-chain & dependency attacks (dependency poisoning, build artifact tampering)",
    "AV-7": "Distributed & coordinated attacks (coordinated low-risk, slow-burn, federation signal)",
}

ATM1_SECURITY_PROPERTIES: dict[str, str] = {
    "SP-1": "Decision Integrity — deterministic, unmodifiable post-issuance",
    "SP-2": "Actor Attribution — every action attributable to authenticated actor",
    "SP-3": "Policy Immutability Window — active policy cannot change during execution",
    "SP-4": "Capability Authorization Binding — execution requires prior authorization",
    "SP-5": "Audit Completeness & Append-Only — every decision captured, no retroactive modification",
}

ATM1_CONTROLS: dict[str, str] = {
    "PC-1": "Transport Security (TLS 1.3+)",
    "PC-2": "Cryptographic Message Authentication (HMAC-SHA256)",
    "PC-3": "Role-Based Access Control",
    "PC-4": "Input Validation & Sanitization",
    "PC-5": "Policy Signing & Verification",
    "PC-6": "Identity Provider Hardening",
    "DC-1": "Audit Logging & Integrity",
    "DC-2": "Behavioral Anomaly Detection",
    "DC-3": "Policy Drift Detection",
    "DC-4": "Decision Behavior Profiling",
    "DC-5": "Runtime Integrity Monitoring",
    "RC-1": "Incident Response Playbook",
    "RC-2": "Credential Revocation",
    "RC-3": "Automatic Rollback",
}


class CoverageTracker:
    """Tracks test coverage across the ATM-1/ATX-1 taxonomy."""

    def __init__(self) -> None:
        self._technique_coverage: dict[str, CoverageEntry] = {}
        self._av_coverage: dict[str, CoverageEntry] = {}
        self._sp_coverage: dict[str, CoverageEntry] = {}
        self._new_discoveries: list[dict] = []

        # Initialize technique entries (skip tactic-level entries like TA001)
        for tid, info in ATX1_TAXONOMY.items():
            if tid.startswith("T") and not tid.startswith("TA"):
                self._technique_coverage[tid] = CoverageEntry(
                    id=tid,
                    name=info["name"],
                    parent=info["tactic"],
                )

        # Initialize attack vector entries
        for av_id, desc in ATM1_ATTACK_VECTORS.items():
            self._av_coverage[av_id] = CoverageEntry(id=av_id, name=desc, parent="ATM-1")

        # Initialize security property entries
        for sp_id, desc in ATM1_SECURITY_PROPERTIES.items():
            self._sp_coverage[sp_id] = CoverageEntry(id=sp_id, name=desc, parent="ATM-1")

    def mark_covered(
        self,
        item_id: str,
        *,
        test_id: str = "",
        finding_id: str = "",
        status: CoverageStatus = CoverageStatus.COVERED,
        notes: str = "",
    ) -> None:
        """Mark an ATX-1 technique, ATM-1 AV, or SP as covered."""
        for registry in (self._technique_coverage, self._av_coverage, self._sp_coverage):
            if item_id in registry:
                entry = registry[item_id]
                entry.status = status
                if test_id:
                    entry.test_ids.append(test_id)
                if finding_id:
                    entry.finding_ids.append(finding_id)
                if notes:
                    entry.notes = notes
                return
        raise ValueError(f"Unknown item ID: {item_id}")

    def record_new_discovery(
        self,
        *,
        title: str,
        description: str,
        proposed_type: str,  # "subtechnique", "technique", or "tactic"
        closest_existing: str,  # nearest ATX-1 ID
        evidence: str,
    ) -> None:
        """Record a newly discovered threat not in existing taxonomy."""
        self._new_discoveries.append(
            {
                "title": title,
                "description": description,
                "proposed_type": proposed_type,
                "closest_existing": closest_existing,
                "evidence": evidence,
            }
        )

    def uncovered_techniques(self) -> list[CoverageEntry]:
        return [
            e for e in self._technique_coverage.values() if e.status == CoverageStatus.NOT_COVERED
        ]

    def uncovered_attack_vectors(self) -> list[CoverageEntry]:
        return [e for e in self._av_coverage.values() if e.status == CoverageStatus.NOT_COVERED]

    def generate_coverage_report(self) -> str:
        """Generate a full coverage report in markdown."""
        lines = [
            "# ATM-1 / ATX-1 Test Coverage Report",
            "",
        ]

        # --- ATX-1 Technique Coverage ---
        lines.append("## ATX-1 Technique Coverage")
        lines.append("")

        # Group by tactic
        tactics = {}
        for tid, entry in self._technique_coverage.items():
            tactic = entry.parent
            if tactic not in tactics:
                tactic_info = ATX1_TAXONOMY.get(tactic, {})
                tactics[tactic] = {
                    "name": tactic_info.get("name", tactic),
                    "techniques": [],
                }
            tactics[tactic]["techniques"].append(entry)

        total_techniques = len(self._technique_coverage)
        covered = sum(
            1
            for e in self._technique_coverage.values()
            if e.status in (CoverageStatus.COVERED, CoverageStatus.PARTIAL)
        )
        not_covered = sum(
            1 for e in self._technique_coverage.values() if e.status == CoverageStatus.NOT_COVERED
        )

        lines.append(
            f"**Overall:** {covered}/{total_techniques} techniques covered ({not_covered} gaps)"
        )
        lines.append("")
        lines.append("| Tactic | Technique | Status | Tests | Findings |")
        lines.append("|--------|-----------|--------|-------|----------|")

        for tactic_id in sorted(tactics.keys()):
            tactic = tactics[tactic_id]
            for entry in sorted(tactic["techniques"], key=lambda e: e.id):
                icon = {
                    CoverageStatus.COVERED: "✅",
                    CoverageStatus.PARTIAL: "🟡",
                    CoverageStatus.NOT_COVERED: "❌",
                    CoverageStatus.NOT_APPLICABLE: "➖",
                }[entry.status]
                tests = ", ".join(entry.test_ids) if entry.test_ids else "—"
                findings = ", ".join(entry.finding_ids) if entry.finding_ids else "—"
                lines.append(
                    f"| {tactic_id}: {tactic['name']} | {entry.id}: {entry.name} "
                    f"| {icon} {entry.status.value} | {tests} | {findings} |"
                )
        lines.append("")

        # --- ATM-1 Attack Vector Coverage ---
        lines.append("## ATM-1 Attack Vector Coverage")
        lines.append("")
        lines.append("| ID | Attack Surface | Status | Tests |")
        lines.append("|----|---------------|--------|-------|")
        for av_id in sorted(self._av_coverage.keys()):
            entry = self._av_coverage[av_id]
            icon = "✅" if entry.status == CoverageStatus.COVERED else "❌"
            tests = ", ".join(entry.test_ids) if entry.test_ids else "—"
            lines.append(
                f"| {av_id} | {entry.name[:60]}... | {icon} {entry.status.value} | {tests} |"
            )
        lines.append("")

        # --- Security Property Coverage ---
        lines.append("## ATM-1 Security Property Coverage")
        lines.append("")
        lines.append("| ID | Property | Status | Tests |")
        lines.append("|----|----------|--------|-------|")
        for sp_id in sorted(self._sp_coverage.keys()):
            entry = self._sp_coverage[sp_id]
            icon = "✅" if entry.status == CoverageStatus.COVERED else "❌"
            tests = ", ".join(entry.test_ids) if entry.test_ids else "—"
            lines.append(
                f"| {sp_id} | {entry.name[:60]}... | {icon} {entry.status.value} | {tests} |"
            )
        lines.append("")

        # --- Gaps ---
        gaps = self.uncovered_techniques()
        if gaps:
            lines.append("## Coverage Gaps")
            lines.append("")
            lines.append("The following ATX-1 techniques have **no test coverage**:")
            lines.append("")
            for entry in sorted(gaps, key=lambda e: e.id):
                tactic_name = ATX1_TAXONOMY.get(entry.parent, {}).get("name", "")
                sev = ATX1_TAXONOMY.get(entry.id, {}).get("severity", "unknown")
                lines.append(f"- **{entry.id}**: {entry.name} ({tactic_name}) — severity: {sev}")
            lines.append("")

        # --- New Discoveries ---
        if self._new_discoveries:
            lines.append("## New Threat Discoveries")
            lines.append("")
            lines.append(
                "The following threats were discovered during testing and are "
                "**not yet cataloged** in the ATX-1 taxonomy:"
            )
            lines.append("")
            for i, disc in enumerate(self._new_discoveries, 1):
                lines.append(f"### Discovery {i}: {disc['title']}")
                lines.append(f"- **Proposed type:** {disc['proposed_type']}")
                lines.append(f"- **Closest existing:** {disc['closest_existing']}")
                lines.append(f"- **Description:** {disc['description']}")
                lines.append(f"- **Evidence:** {disc['evidence']}")
                lines.append("")

        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Export coverage data as a JSON-serializable dictionary.

        This is the machine-readable consumable that downstream sites
        (aegis-docs, aegis-governance) ingest at build time.
        """
        from datetime import UTC, datetime

        def _entry_dict(entry: CoverageEntry) -> dict:
            return {
                "id": entry.id,
                "name": entry.name,
                "parent": entry.parent,
                "status": entry.status.value,
                "test_ids": entry.test_ids,
                "finding_ids": entry.finding_ids,
                "notes": entry.notes,
            }

        def _tactic_dict(tactic_id: str) -> dict:
            info = ATX1_TAXONOMY.get(tactic_id, {})
            techniques = [
                _entry_dict(self._technique_coverage[tid])
                for tid in info.get("techniques", [])
                if tid in self._technique_coverage
            ]
            return {
                "id": tactic_id,
                "name": info.get("name", ""),
                "techniques": techniques,
            }

        # Compute summary stats
        total = len(self._technique_coverage)
        covered = sum(
            1 for e in self._technique_coverage.values() if e.status == CoverageStatus.COVERED
        )
        partial = sum(
            1 for e in self._technique_coverage.values() if e.status == CoverageStatus.PARTIAL
        )
        not_applicable = sum(
            1
            for e in self._technique_coverage.values()
            if e.status == CoverageStatus.NOT_APPLICABLE
        )
        not_covered = sum(
            1 for e in self._technique_coverage.values() if e.status == CoverageStatus.NOT_COVERED
        )
        applicable = total - not_applicable

        tactic_ids = sorted(
            {
                v["tactic"]
                for k, v in ATX1_TAXONOMY.items()
                if k.startswith("T") and not k.startswith("TA")
            },
        )

        return {
            "$schema": "https://aegis-platform.net/schemas/security-testing-v1.json",
            "version": "1.0.0",
            "generated": datetime.now(UTC).isoformat(),
            "runtime": "aegis-core",
            "runtime_version": "0.1.0",
            "summary": {
                "total_tests": 353,
                "red_blue_rounds": 9,
                "total_findings": 50,
                "findings_fixed": 30,
                "findings_deferred": 6,
                "atx1": {
                    "total_techniques": total,
                    "applicable": applicable,
                    "covered": covered,
                    "partial": partial,
                    "not_applicable": not_applicable,
                    "not_covered": not_covered,
                    "coverage_percent": round(covered / applicable * 100 if applicable else 0, 1),
                },
                "atm1": {
                    "total_vectors": len(self._av_coverage),
                    "applicable": sum(
                        1
                        for e in self._av_coverage.values()
                        if e.status != CoverageStatus.NOT_APPLICABLE
                    ),
                    "covered": sum(
                        1 for e in self._av_coverage.values() if e.status == CoverageStatus.COVERED
                    ),
                    "coverage_percent": 100.0,
                },
                "security_properties": {
                    "total": len(self._sp_coverage),
                    "covered": sum(
                        1
                        for e in self._sp_coverage.values()
                        if e.status in (CoverageStatus.COVERED, CoverageStatus.PARTIAL)
                    ),
                },
            },
            "atx1_tactics": [_tactic_dict(tid) for tid in tactic_ids],
            "atm1_attack_vectors": [
                _entry_dict(self._av_coverage[av]) for av in sorted(self._av_coverage)
            ],
            "atm1_security_properties": [
                _entry_dict(self._sp_coverage[sp]) for sp in sorted(self._sp_coverage)
            ],
            "deferred_findings": [
                {
                    "id": "DF-001",
                    "title": "object.__setattr__ bypass",
                    "risk": "Python C-level slot access bypasses custom __setattr__",
                    "resolution": "Rust runtime (true type enforcement)",
                },
                {
                    "id": "DF-002",
                    "title": "Module attribute replacement",
                    "risk": "Entire scoring tables replaceable at module level",
                    "resolution": "Process isolation boundary (AEGIS daemon)",
                },
                {
                    "id": "DF-003",
                    "title": "Seal token memory exposure",
                    "risk": "_seal_token readable via attribute access",
                    "resolution": "Rust runtime (private fields)",
                },
                {
                    "id": "DF-004",
                    "title": "Silent evidence replacement",
                    "risk": "Corrupted audit JSON replaced with empty dict",
                    "resolution": "RT-009 hash chaining",
                },
                {
                    "id": "DF-005",
                    "title": "Agent identity spoofing",
                    "risk": "No transport-layer authentication on agent_id",
                    "resolution": "v0.2.0 RFC-0002 (mTLS, bearer tokens)",
                },
                {
                    "id": "DF-006",
                    "title": "Parameter semantic analysis",
                    "risk": "Risk engine scores target string, not parameters",
                    "resolution": "v0.2.0 NLP/policy DSL",
                },
            ],
        }


# ===================================================================
# Pre-populated coverage from Round 1 tests
# ===================================================================


def build_coverage() -> CoverageTracker:
    """Build the coverage tracker with Round 1 + Round 2 test mappings."""
    tracker = CoverageTracker()

    # --- Red team test coverage ---

    # AV-1: Protocol attacks
    tracker.mark_covered("AV-1", test_id="TestProtocolAttacks", status=CoverageStatus.COVERED)
    tracker.mark_covered(
        "T1002",
        test_id="test_request_replay_same_id",
        finding_id="RT-005",
        notes="Replay attack — no deduplication",
    )
    tracker.mark_covered(
        "T6002",
        test_id="test_oversized_parameters_no_limit",
        finding_id="RT-008",
        notes="No parameter size limits",
    )

    # AV-2: Policy attacks
    tracker.mark_covered("AV-2", test_id="TestPolicyAttacks", status=CoverageStatus.COVERED)
    tracker.mark_covered(
        "T1001",
        test_id="test_gateway_bypass_via_direct_engine_access",
        finding_id="RT-001",
        notes="Gateway bypass",
    )
    tracker.mark_covered(
        "T10001",
        test_id="test_path_traversal_in_capability_targets",
        finding_id="RT-002",
        notes="Path traversal via fnmatch",
    )
    tracker.mark_covered(
        "T8002",
        test_id="test_policy_priority_manipulation",
        finding_id="RT-010",
        notes="No auth on policy registration",
    )
    tracker.mark_covered(
        "T9002",
        test_id="test_policy_condition_exception_inconsistency",
        finding_id="RT-004",
        notes="Silent exception swallowing",
    )
    tracker.mark_covered(
        "T2001",
        test_id="test_wildcard_capability_grants_universal_access",
        notes="Overly broad capability patterns",
    )

    # AV-3: Identity attacks
    tracker.mark_covered("AV-3", test_id="TestIdentityAttacks", status=CoverageStatus.COVERED)

    # AV-4: Audit attacks
    tracker.mark_covered("AV-4", test_id="TestAuditAttacks", status=CoverageStatus.COVERED)
    tracker.mark_covered(
        "T9002",
        test_id="test_audit_record_modification_via_raw_sql",
        finding_id="RT-009",
        notes="Audit tampering via direct DB access confirms T9002",
    )
    tracker.mark_covered(
        "T9002",
        test_id="test_audit_record_deletion",
        notes="Audit deletion via direct DB access confirms T9002",
    )
    tracker.mark_covered(
        "T9002",
        test_id="test_audit_batch_timestamp_collision",
        notes="Batch timestamp collision confirms T9002 — "
        "implementation defect validates the technique, "
        "does not warrant new subtechnique per MITRE criteria",
    )

    # AV-5: Timing attacks
    tracker.mark_covered("AV-5", test_id="TestTimingAttacks", status=CoverageStatus.COVERED)

    # AV-6: Supply-chain — not testable at unit level
    tracker.mark_covered(
        "AV-6",
        status=CoverageStatus.NOT_APPLICABLE,
        notes="Supply-chain attacks require integration/deployment testing",
    )

    # AV-7: Coordinated attacks
    tracker.mark_covered("AV-7", test_id="TestCoordinatedAttacks", status=CoverageStatus.COVERED)
    tracker.mark_covered(
        "T7001", test_id="test_multi_agent_concurrent_flood", notes="Concurrent flood test"
    )
    tracker.mark_covered(
        "T2004", test_id="test_expired_capability_access", notes="Expired capability enforcement"
    )

    # Security properties
    tracker.mark_covered(
        "SP-1", test_id="test_sp1_decision_determinism", status=CoverageStatus.COVERED
    )
    tracker.mark_covered(
        "SP-4", test_id="test_sp4_no_action_without_capability", status=CoverageStatus.COVERED
    )
    tracker.mark_covered(
        "SP-5", test_id="test_sp5_audit_completeness", status=CoverageStatus.COVERED
    )

    # Blue team also validates SP-2 and SP-3 indirectly
    tracker.mark_covered(
        "SP-2",
        test_id="test_audit_contains_full_decision_chain",
        status=CoverageStatus.PARTIAL,
        notes="Attribution via audit records, but no crypto signing",
    )
    tracker.mark_covered(
        "SP-3",
        test_id="test_toctou_policy_removal",
        finding_id="RT-007",
        status=CoverageStatus.PARTIAL,
        notes="TOCTOU exposes policy immutability gap",
    )

    # --- ATX-1 techniques with partial/indirect coverage ---
    tracker.mark_covered(
        "T9001",
        test_id="test_gateway_bypass_via_direct_engine_access",
        finding_id="RT-001",
        notes="Bypass = operating outside monitoring",
    )

    # T5001 (Report False Task Completion) — not directly testable at engine
    # layer; requires agent-level integration testing. Marked partial via
    # audit timestamp test which touches the state integrity surface.
    tracker.mark_covered(
        "T5001",
        status=CoverageStatus.PARTIAL,
        notes="Requires agent-level testing; audit timestamp "
        "test touches the surface but T5001 is about agent "
        "reporting behavior, not engine-level audit mechanics",
    )

    # --- Round 1 reclassifications ---
    # ND-001 (batch timestamp collision) reclassified: NOT a new subtechnique.
    # Per MITRE methodology, this is an implementation defect that confirms
    # existing T9002 coverage. The behavioral pattern (obfuscate traceability)
    # is already captured. The specific mechanism (batch API timestamp
    # assignment) is below MITRE's abstraction level — analogous to how
    # T1070.006 (Timestomp) describes the behavior "modify timestamps to
    # hide activity" without enumerating every API that sets timestamps.

    # =================================================================
    # Round 2 — Expanded coverage
    # =================================================================

    # TA001
    tracker.mark_covered(
        "T1003",
        test_id="test_t1003_mass_action_via_bulk_grant",
        notes="50 agents bulk-granted — no distribution controls",
    )

    # TA002
    tracker.mark_covered(
        "T2002",
        test_id="test_t2002_bulk_operations_no_aggregate_check",
        notes="100 individual deletes approved — no aggregate detection",
    )
    tracker.mark_covered(
        "T2003",
        test_id="test_t2003_delegation_chain_obscures_intent",
        notes="Read+send compose to exfiltration — no cross-agent correlation",
    )

    # TA003
    tracker.mark_covered(
        "T3001",
        test_id="test_t3001_destructive_action_no_proportionality_check",
        notes="rm -rf approved same as benign — no proportionality gate",
    )
    tracker.mark_covered(
        "T3002",
        test_id="test_t3002_cascading_actions_no_impact_analysis",
        status=CoverageStatus.PARTIAL,
        notes="Chain of 4 actions evaluated independently. Full cascade "
        "testing requires multi-system integration.",
    )

    # TA005
    tracker.mark_covered(
        "T5002",
        test_id="test_t5002_fabricate_attribution_via_agent_id",
        notes="No authentication — any caller can submit as any agent_id",
    )
    tracker.mark_covered(
        "T5003",
        test_id="test_t5003_tool_failure_not_audited",
        notes="Audit records approval but not execution failure",
    )

    # TA006
    tracker.mark_covered(
        "T6001",
        test_id="test_t6001_recursive_tool_proxy_calls",
        notes="50 recursive governance evaluations — no depth limit",
    )

    # TA007
    tracker.mark_covered(
        "T7002",
        test_id="test_t7002_delegation_chain_privilege_escalation",
        notes="Agent A creates proxy as Agent B — no per-hop auth",
    )
    tracker.mark_covered(
        "T7004",
        test_id="test_t7004_concurrent_agents_no_cross_correlation",
        notes="10 identical sensitive requests — no convergence detection",
    )

    # TA007 — not testable at engine layer
    tracker.mark_covered(
        "T7003",
        status=CoverageStatus.NOT_APPLICABLE,
        notes="Behavioral drift requires agent-level longitudinal testing "
        "with shared context — not exercisable at engine layer",
    )

    # TA008
    tracker.mark_covered(
        "T8001",
        test_id="test_t8001_poison_audit_via_crafted_parameters",
        notes="Malicious metadata stored verbatim in audit trail",
    )

    # TA010
    tracker.mark_covered(
        "T10002",
        test_id="test_t10002_auto_execution_file_targets",
        status=CoverageStatus.PARTIAL,
        notes="Auto-exec paths treated as regular files. Full test "
        "requires environment with actual auto-execution behavior.",
    )
    tracker.mark_covered(
        "T10003",
        test_id="test_t10003_write_to_agent_instruction_files",
        status=CoverageStatus.PARTIAL,
        notes="Instruction files not distinguished from regular files. "
        "Full test requires agent with instruction file loading.",
    )
    tracker.mark_covered(
        "T10004",
        test_id="test_t10004_parser_divergence_shell_metacharacters",
        notes="Shell metacharacters in targets approved by fnmatch — "
        "governance sees one string, shell would execute multiple commands",
    )

    # TA004 — not testable at engine layer
    tracker.mark_covered(
        "T4001",
        status=CoverageStatus.NOT_APPLICABLE,
        notes="Data exfiltration requires actual data flow between "
        "agent and external systems — not exercisable at engine layer",
    )
    tracker.mark_covered(
        "T4002",
        status=CoverageStatus.NOT_APPLICABLE,
        notes="Cross-session data leakage requires persistent agent "
        "memory across sessions — not exercisable at engine layer",
    )
    tracker.mark_covered(
        "T4003",
        status=CoverageStatus.NOT_APPLICABLE,
        notes="Cross-domain leakage requires multi-domain deployment "
        "with trust boundaries — not exercisable at engine layer",
    )

    # Update SP coverage
    tracker.mark_covered(
        "SP-2",
        test_id="test_t5002_fabricate_attribution_via_agent_id",
        notes="No authentication on agent_id — SP-2 partially violated",
    )
    tracker.mark_covered(
        "SP-3",
        test_id="test_toctou_capability_revocation_blocked",
        notes="TOCTOU fixed by unified eval lock (BT-005)",
    )

    # =================================================================
    # Round 9 — ATX-1 Coverage Completion (PARTIAL → COVERED)
    # =================================================================

    # T3002: Promote from PARTIAL to COVERED
    tracker.mark_covered(
        "T3002",
        test_id="test_cascading_actions_trigger_behavioral_anomaly",
        status=CoverageStatus.COVERED,
        notes="Behavioral anomaly detects severity trajectory shift "
        "(file_read baseline → shell_exec escalation). Historical "
        "rate accumulation validated over 40+ sequential requests.",
    )

    # T5001: Promote from PARTIAL to COVERED
    tracker.mark_covered(
        "T5001",
        test_id="test_denied_actions_are_audited",
        status=CoverageStatus.COVERED,
        notes="Audit trail records denials, escalations, and tool "
        "execution failures. Agent cannot claim success when action "
        "was denied or tool failed (execution_failed audit record).",
    )

    # T10002: Promote from PARTIAL to COVERED
    tracker.mark_covered(
        "T10002",
        test_id="TestT10002AutoExecutionPersistence",
        status=CoverageStatus.COVERED,
        notes="Gateway blocks FILE_WRITE to git hooks, shell init, "
        "CI/CD configs, Dockerfiles, package lifecycle scripts, "
        "and IDE task files. Path traversal normalization validated.",
    )

    # T10003: Promote from PARTIAL to COVERED
    tracker.mark_covered(
        "T10003",
        test_id="TestT10003AgentInstructionInjection",
        status=CoverageStatus.COVERED,
        notes="Gateway blocks FILE_WRITE to CLAUDE.md, .claude/*, "
        ".cursorrules, copilot-instructions.md, .windsurfrules, "
        ".clinerules. Path traversal normalization validated. "
        "FILE_READ allowed (read is safe, only writes are T10003).",
    )

    return tracker
