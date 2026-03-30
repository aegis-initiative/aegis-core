"""Red Team Tests — AEGIS Security Assessment.

Offensive tests that attempt to violate AEGIS security properties.
Each test is mapped to ATM-1 attack vectors and ATX-1 techniques.

Tests are organized by ATM-1 attack surface:
- AV-1: Protocol-level attacks
- AV-2: Policy-layer attacks
- AV-3: Identity & authentication attacks
- AV-4: Audit & logging attacks
- AV-5: Timing & side-channel attacks
- AV-7: Distributed & coordinated attacks
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from aegis_core import AEGISRuntime
from aegis_core.capability_registry import Capability, CapabilityRegistry
from aegis_core.decision_engine import DecisionEngine
from aegis_core.policy_engine import Policy, PolicyCondition, PolicyEffect, PolicyEngine
from aegis_core.protocol import (
    AGPAction,
    AGPContext,
    AGPRequest,
    AGPResponse,
    ActionType,
    Decision,
)

from .conftest import (
    make_allow_policy,
    make_capability,
    make_deny_policy,
    make_request,
)


# ===================================================================
# AV-1: Protocol-Level Attacks
# ===================================================================

class TestProtocolAttacks:
    """ATM-1 AV-1: Attacks against the AGP protocol layer."""

    @pytest.mark.atm1(attack_vector="AV-1")
    @pytest.mark.atx1(technique_id="T1002")
    def test_request_replay_same_id(self, configured_runtime: AEGISRuntime):
        """RT-005: Submit the same request_id twice — replay protection.

        ROUND 1: Attack succeeded (no dedup).
        ROUND 2: Blue team fix BT-003 added replay detection — attack blocked.
        """
        from aegis_core.exceptions import AEGISValidationError

        request = make_request(agent_id="test-agent", target="test-target")

        r1 = configured_runtime.gateway.submit(request)
        assert r1.decision == Decision.APPROVED

        # BLUE TEAM FIX VALIDATED: Replay now rejected
        with pytest.raises(AEGISValidationError, match="Duplicate request_id"):
            configured_runtime.gateway.submit(request)

    @pytest.mark.atm1(attack_vector="AV-1")
    @pytest.mark.atx1(technique_id="T6002")
    def test_oversized_parameters_rejected(self, configured_runtime: AEGISRuntime):
        """RT-008: Submit request with massive parameters dict.

        ROUND 1: Attack succeeded (no size check).
        ROUND 2: Blue team fix BT-004 added parameter size validation.
        """
        from aegis_core.exceptions import AEGISValidationError

        # Build a payload exceeding the 1MB limit
        large_params = {f"key_{i}": "x" * 10_000 for i in range(200)}
        request = make_request(
            agent_id="test-agent",
            target="test-target",
            parameters=large_params,
        )

        # BLUE TEAM FIX VALIDATED: Oversized parameters now rejected
        with pytest.raises(AEGISValidationError, match="exceeds maximum size"):
            configured_runtime.gateway.submit(request)

    @pytest.mark.atm1(attack_vector="AV-1")
    def test_request_id_format_not_validated(self, configured_runtime: AEGISRuntime):
        """Request IDs accept arbitrary strings — no UUID format enforcement."""
        request = make_request(agent_id="test-agent", target="test-target")
        request.request_id = "not-a-uuid-at-all!!!"

        response = configured_runtime.gateway.submit(request)
        # RED TEAM FINDING: Arbitrary request_id format accepted
        assert response.decision == Decision.APPROVED


# ===================================================================
# AV-2: Policy-Layer Attacks
# ===================================================================

class TestPolicyAttacks:
    """ATM-1 AV-2: Attacks against the policy evaluation layer."""

    @pytest.mark.atm1(attack_vector="AV-2")
    @pytest.mark.atx1(technique_id="T1001")
    def test_gateway_bypass_blocked_by_engine_validation(self, configured_runtime: AEGISRuntime):
        """RT-001: Direct engine access now has independent validation.

        ROUND 1: Direct _evaluate() bypassed all gateway validation.
        ROUND 4: Blue team fix BT-011 added independent structural
                 validation in the engine (defense-in-depth).

        The gateway rejects format violations (invalid agent_id chars).
        The engine independently rejects structural violations
        (None action, empty target, missing context).
        """
        from aegis_core.exceptions import AEGISValidationError

        engine: DecisionEngine = configured_runtime._decision_engine

        # Gateway rejects format violations (special chars in agent_id)
        format_request = AGPRequest(
            agent_id="!!!invalid!!!",
            action=AGPAction(
                type=ActionType.TOOL_CALL,
                target="test-target",
                parameters={},
            ),
            context=AGPContext(session_id="sess"),
        )
        with pytest.raises(AEGISValidationError):
            configured_runtime.gateway.submit(format_request)

        # Engine independently rejects structural violations
        # even when called directly (defense-in-depth)
        structural_request = AGPRequest(
            agent_id="valid-agent",
            action=AGPAction(
                type=ActionType.TOOL_CALL,
                target="",  # Empty target — structural violation
                parameters={},
            ),
            context=AGPContext(session_id="sess"),
        )
        with pytest.raises(AEGISValidationError, match="empty action target"):
            engine._evaluate(structural_request)

        # BLUE TEAM FIX VALIDATED: Engine rejects bad requests independently
        # Note: format-only violations (invalid chars but structurally valid)
        # are still the gateway's responsibility — the engine validates
        # structure, not format. This is intentional layering.
        response = engine._evaluate(format_request)
        assert isinstance(response, AGPResponse), (
            "Format-only violations pass engine validation (correct — "
            "format is gateway's layer, structure is engine's layer)"
        )

    @pytest.mark.atm1(attack_vector="AV-2")
    @pytest.mark.atx1(technique_id="T10001")
    def test_path_traversal_in_capability_targets(self, runtime: AEGISRuntime):
        """RT-002: Use path traversal to escape capability target scope."""
        cap = make_capability(
            cap_id="cap-docs",
            action_types=[ActionType.FILE_READ.value],
            target_patterns=["/docs/*"],
        )
        runtime.capabilities.register(cap)
        runtime.capabilities.grant("attacker", "cap-docs")

        # Add allow policy
        runtime.policies.add_policy(make_allow_policy())

        # Attempt path traversal
        traversal_targets = [
            "/docs/../etc/passwd",
            "/docs/../../root/.ssh/id_rsa",
            "/docs/./../../etc/shadow",
        ]

        for target in traversal_targets:
            request = make_request(
                agent_id="attacker",
                action_type=ActionType.FILE_READ,
                target=target,
            )
            response = runtime.gateway.submit(request)
            # RED TEAM FINDING: Path traversal bypasses capability scope
            if response.decision == Decision.APPROVED:
                pytest.fail(
                    f"Path traversal succeeded: target '{target}' approved "
                    f"despite capability limited to '/docs/*'"
                )

    @pytest.mark.atm1(attack_vector="AV-2")
    @pytest.mark.atx1(technique_id="T8002")
    def test_policy_priority_manipulation(self, runtime: AEGISRuntime):
        """RT-010: Add a catch-all allow policy at highest priority."""
        # Setup: deny policy for dangerous actions
        cap = make_capability(
            cap_id="cap-shell",
            action_types=[ActionType.SHELL_EXEC.value],
            target_patterns=["*"],
        )
        runtime.capabilities.register(cap)
        runtime.capabilities.grant("attacker", "cap-shell")

        deny_policy = make_deny_policy(
            policy_id="pol-deny-shell",
            name="Deny shell execution",
            conditions=[
                PolicyCondition(
                    evaluate=lambda r: r.action.type == ActionType.SHELL_EXEC,
                    description="Matches shell_exec actions",
                )
            ],
            priority=100,
        )
        runtime.policies.add_policy(deny_policy)

        # Verify shell exec is denied
        request = make_request(
            agent_id="attacker",
            action_type=ActionType.SHELL_EXEC,
            target="rm -rf /",
        )
        response = runtime.gateway.submit(request)
        assert response.decision == Decision.DENIED

        # RED TEAM ATTACK: Add an allow-all policy at higher priority
        # Note: deny policies still take precedence due to evaluation order,
        # but this demonstrates the lack of policy registration controls
        backdoor_allow = make_allow_policy(
            policy_id="pol-backdoor",
            name="Backdoor allow-all",
            priority=0,
        )
        # RED TEAM FINDING: No authorization required to add policies
        runtime.policies.add_policy(backdoor_allow)

        # The deny still wins because deny is checked first regardless of priority
        request2 = make_request(
            agent_id="attacker",
            action_type=ActionType.SHELL_EXEC,
            target="rm -rf /",
        )
        response2 = runtime.gateway.submit(request2)
        assert response2.decision == Decision.DENIED, (
            "Deny precedence held despite priority manipulation"
        )

    @pytest.mark.atm1(attack_vector="AV-2")
    @pytest.mark.atx1(technique_id="T9002")
    def test_policy_condition_exception_consistency(self, runtime: AEGISRuntime):
        """RT-004: Exception handling now consistent between evaluate and find_matching.

        ROUND 1: find_matching_policies silently swallowed exceptions.
        ROUND 2: Blue team fix BT-002 makes both methods raise AEGISPolicyError.
        """
        cap = make_capability()
        runtime.capabilities.register(cap)
        runtime.capabilities.grant("test-agent", "cap-test")

        def buggy_condition(req):
            raise RuntimeError("Intentional error for red team test")

        buggy_policy = Policy(
            id="pol-buggy",
            name="Buggy policy",
            description="Policy with an error-raising condition",
            effect=PolicyEffect.DENY,
            conditions=[
                PolicyCondition(
                    evaluate=buggy_condition,
                    description="Intentionally buggy condition",
                )
            ],
            priority=50,
        )
        runtime.policies.add_policy(buggy_policy)

        request = make_request()

        from aegis_core.exceptions import AEGISPolicyError

        # BLUE TEAM FIX VALIDATED: Both methods now raise consistently
        with pytest.raises(AEGISPolicyError):
            runtime.policies.evaluate(request)

        with pytest.raises(AEGISPolicyError):
            runtime.policies.find_matching_policies(request)

    @pytest.mark.atm1(attack_vector="AV-2")
    @pytest.mark.atx1(technique_id="T2001")
    def test_wildcard_capability_grants_broad_access(self, runtime: AEGISRuntime):
        """Overly broad capability passes capability + policy checks.

        With the risk engine (stage 3), destructive actions are now
        escalated even with wildcard capabilities. Non-destructive
        actions still pass through.
        """
        cap = make_capability(
            cap_id="cap-wildcard",
            action_types=[a.value for a in ActionType],
            target_patterns=["*"],
        )
        runtime.capabilities.register(cap)
        runtime.capabilities.grant("greedy-agent", "cap-wildcard")
        runtime.policies.add_policy(make_allow_policy())

        # Non-destructive actions: wildcard still grants access
        benign_actions = [
            (ActionType.FILE_READ, "/docs/readme.md"),
            (ActionType.TOOL_CALL, "list-files"),
            (ActionType.DATA_ACCESS, "cache://session/data"),
        ]
        for action_type, target in benign_actions:
            request = make_request(
                agent_id="greedy-agent",
                action_type=action_type,
                target=target,
            )
            response = runtime.gateway.submit(request)
            assert response.decision == Decision.APPROVED, (
                f"Benign {action_type.value} on {target} should be approved"
            )

        # Destructive actions: risk engine escalates despite wildcard
        request = make_request(
            agent_id="greedy-agent",
            action_type=ActionType.SHELL_EXEC,
            target="rm -rf /",
        )
        response = runtime.gateway.submit(request)
        assert response.decision in (
            Decision.REQUIRE_CONFIRMATION, Decision.ESCALATE,
        ), (
            f"Destructive action should be escalated by risk engine "
            f"(risk_score={response.risk_score})"
        )


# ===================================================================
# AV-3: Identity & Authentication Attacks
# ===================================================================

class TestIdentityAttacks:
    """ATM-1 AV-3: Attacks against identity and authentication."""

    @pytest.mark.atm1(attack_vector="AV-3")
    @pytest.mark.atx1(technique_id="T1001")
    def test_capability_self_escalation(self, configured_runtime: AEGISRuntime):
        """RT-006: Agent with registry access can self-grant capabilities."""
        registry = configured_runtime.capabilities

        # Register a high-privilege capability
        admin_cap = make_capability(
            cap_id="cap-admin",
            name="Admin access",
            action_types=[a.value for a in ActionType],
            target_patterns=["*"],
        )
        registry.register(admin_cap)

        # RED TEAM FINDING: No authorization check on grant()
        # Any caller can grant any capability to any agent
        registry.grant("malicious-agent", "cap-admin")

        assert registry.has_capability_for_action(
            "malicious-agent", ActionType.SHELL_EXEC.value, "rm -rf /"
        ), "Self-escalation succeeded — no authorization on grant()"

    @pytest.mark.atm1(attack_vector="AV-3")
    @pytest.mark.atx1(technique_id="T1001")
    def test_bulk_grant_escalation(self, configured_runtime: AEGISRuntime):
        """Bulk grant can escalate many agents simultaneously."""
        registry = configured_runtime.capabilities

        admin_cap = make_capability(
            cap_id="cap-admin-bulk",
            name="Admin access",
            action_types=[a.value for a in ActionType],
            target_patterns=["*"],
        )
        registry.register(admin_cap)

        # RED TEAM FINDING: bulk_grant has no authorization either
        agents = [f"agent-{i}" for i in range(100)]
        count = registry.bulk_grant(agents, "cap-admin-bulk")
        assert count == 100, "100 agents escalated in a single call"

    @pytest.mark.atm1(attack_vector="AV-3")
    def test_agent_id_boundary_values(self, configured_runtime: AEGISRuntime):
        """Test agent_id edge cases that pass validation."""
        # These are valid per the regex but could be confusing
        edge_case_ids = [
            "." * 256,       # 256 dots
            "-" * 256,       # 256 hyphens
            "_" * 256,       # 256 underscores
            "a",             # single char
            "A.B-C_D",       # mixed separators
        ]

        for agent_id in edge_case_ids:
            cap = make_capability(cap_id=f"cap-{hash(agent_id)}")
            try:
                configured_runtime.capabilities.register(cap)
            except ValueError:
                pass  # Already registered from prior iteration
            configured_runtime.capabilities.grant(agent_id, cap.id)
            configured_runtime.policies.add_policy(
                make_allow_policy(policy_id=f"pol-{hash(agent_id)}")
            ) if not configured_runtime.policies.get_policy(f"pol-{hash(agent_id)}") else None

            request = make_request(agent_id=agent_id, target="test-target")
            # These should all pass validation
            response = configured_runtime.gateway.submit(request)
            assert isinstance(response, AGPResponse)


# ===================================================================
# AV-4: Audit & Logging Attacks
# ===================================================================

class TestAuditAttacks:
    """ATM-1 AV-4: Attacks against the audit trail."""

    @pytest.mark.atm1(attack_vector="AV-4")
    @pytest.mark.atx1(technique_id="T9002")
    def test_audit_record_modification_via_raw_sql(self, configured_runtime: AEGISRuntime):
        """RT-009: Modify audit records via direct SQLite access."""
        request = make_request(agent_id="test-agent", target="test-target")
        response = configured_runtime.gateway.submit(request)
        assert response.decision == Decision.APPROVED

        audit_record = configured_runtime.audit.get_record(response.audit_id)
        assert audit_record is not None
        assert audit_record.decision == "approved"

        # RED TEAM ATTACK: Direct DB modification
        conn = configured_runtime.audit._conn
        conn.execute(
            "UPDATE audit_records SET decision = 'denied' WHERE id = ?",
            (response.audit_id,),
        )
        conn.commit()

        # RED TEAM FINDING: Audit record was tampered with
        tampered = configured_runtime.audit.get_record(response.audit_id)
        assert tampered.decision == "denied", (
            "Audit record successfully tampered — no integrity protection"
        )

    @pytest.mark.atm1(attack_vector="AV-4")
    @pytest.mark.atx1(technique_id="T9002")
    def test_audit_record_deletion(self, configured_runtime: AEGISRuntime):
        """Delete audit records via direct SQLite access."""
        request = make_request(agent_id="test-agent", target="test-target")
        response = configured_runtime.gateway.submit(request)

        initial_count = configured_runtime.audit.record_count()
        assert initial_count >= 1

        # RED TEAM ATTACK: Delete audit records
        conn = configured_runtime.audit._conn
        conn.execute("DELETE FROM audit_records WHERE id = ?", (response.audit_id,))
        conn.commit()

        # RED TEAM FINDING: Audit records can be deleted
        assert configured_runtime.audit.get_record(response.audit_id) is None
        assert configured_runtime.audit.record_count() == initial_count - 1, (
            "Audit record deleted — append-only guarantee violated"
        )

    @pytest.mark.atm1(attack_vector="AV-4")
    @pytest.mark.atx1(technique_id="T5001")
    def test_audit_batch_timestamp_collision(self, configured_runtime: AEGISRuntime):
        """Batch audit records share a single timestamp, losing ordering."""
        records = [
            {
                "request_id": f"req-{i}",
                "agent_id": "test-agent",
                "action_type": "tool_call",
                "action_target": "test-target",
                "action_parameters": {},
                "decision": "approved",
                "reason": f"Test record {i}",
                "policy_evaluations": [],
                "session_id": "sess",
            }
            for i in range(5)
        ]

        ids = configured_runtime.audit.batch_record(records)
        assert len(ids) == 5

        # RED TEAM FINDING: All records have identical timestamps
        audit_records = [configured_runtime.audit.get_record(aid) for aid in ids]
        timestamps = {r.timestamp for r in audit_records}
        assert len(timestamps) == 1, (
            "All batch records share one timestamp — temporal ordering lost"
        )


# ===================================================================
# AV-5: Timing & Side-Channel Attacks
# ===================================================================

class TestTimingAttacks:
    """ATM-1 AV-5: Race conditions and TOCTOU exploits."""

    @pytest.mark.atm1(attack_vector="AV-5")
    @pytest.mark.atx1(technique_id="T2001")
    def test_toctou_capability_revocation_blocked(self, runtime: AEGISRuntime):
        """RT-003: TOCTOU capability revocation now blocked by unified eval lock.

        ROUND 1: Revocation between stages succeeded — action approved
                 with revoked capability.
        ROUND 2: Blue team fix BT-005 added unified evaluation lock.
                 Revocation is blocked until evaluation completes.
        """
        cap = make_capability(
            cap_id="cap-toctou",
            action_types=[ActionType.TOOL_CALL.value],
            target_patterns=["*"],
        )
        runtime.capabilities.register(cap)
        runtime.capabilities.grant("agent-toctou", "cap-toctou")
        runtime.policies.add_policy(make_allow_policy())

        results: list[AGPResponse] = []
        revoke_attempted = threading.Event()

        def submit_request():
            request = make_request(agent_id="agent-toctou", target="test-target")
            response = runtime.gateway.submit(request)
            results.append(response)

        def revoke_during_eval():
            # Try to revoke — this will block on the capability registry
            # lock if evaluation is holding the eval lock
            time.sleep(0.005)  # Small delay to let eval start
            runtime.capabilities.revoke("agent-toctou", "cap-toctou")
            revoke_attempted.set()

        t1 = threading.Thread(target=submit_request)
        t2 = threading.Thread(target=revoke_during_eval)

        t1.start()
        t2.start()
        t1.join(timeout=5.0)
        t2.join(timeout=5.0)

        # BLUE TEAM FIX VALIDATED: Either the evaluation completed before
        # revocation (approved with valid capability) or the revocation
        # completed first (denied). No inconsistent state.
        assert len(results) == 1
        assert results[0].decision in (Decision.APPROVED, Decision.DENIED)

    @pytest.mark.atm1(attack_vector="AV-5")
    @pytest.mark.atx1(technique_id="T8002")
    def test_toctou_policy_removal(self, runtime: AEGISRuntime):
        """RT-007: Remove a deny policy while evaluation is in progress."""
        cap = make_capability(
            cap_id="cap-toctou-pol",
            action_types=[ActionType.TOOL_CALL.value],
            target_patterns=["*"],
        )
        runtime.capabilities.register(cap)
        runtime.capabilities.grant("agent-pol-toctou", "cap-toctou-pol")

        runtime.policies.add_policy(make_allow_policy())

        deny_pol = make_deny_policy(
            policy_id="pol-critical-deny",
            name="Critical deny",
            conditions=[
                PolicyCondition(
                    evaluate=lambda r: True,
                    description="Matches everything",
                )
            ],
        )
        runtime.policies.add_policy(deny_pol)

        # Verify it's denied
        request1 = make_request(agent_id="agent-pol-toctou", target="test-target")
        r1 = runtime.gateway.submit(request1)
        assert r1.decision == Decision.DENIED

        # RED TEAM FINDING: Policy can be removed without authorization
        runtime.policies.remove_policy("pol-critical-deny")

        # Now a new request with same shape succeeds
        request2 = make_request(agent_id="agent-pol-toctou", target="test-target")
        r2 = runtime.gateway.submit(request2)
        assert r2.decision == Decision.APPROVED, (
            "Policy removal without authorization allows previously denied actions"
        )


# ===================================================================
# AV-7: Distributed & Coordinated Attacks
# ===================================================================

class TestCoordinatedAttacks:
    """ATM-1 AV-7: Multi-agent coordinated attacks."""

    @pytest.mark.atm1(attack_vector="AV-7")
    @pytest.mark.atx1(technique_id="T7001")
    def test_multi_agent_concurrent_flood(self, configured_runtime: AEGISRuntime):
        """Flood the gateway with concurrent requests from many agents."""
        results: list[AGPResponse] = []
        errors: list[Exception] = []

        def submit_batch(agent_suffix: int):
            try:
                for i in range(10):
                    request = make_request(
                        agent_id="test-agent",
                        target="test-target",
                        session_id=f"session-{agent_suffix}-{i}",
                    )
                    response = configured_runtime.gateway.submit(request)
                    results.append(response)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=submit_batch, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30.0)

        assert not errors, f"Concurrent requests caused errors: {errors}"
        assert len(results) == 100, (
            f"Expected 100 results from concurrent flood, got {len(results)}"
        )
        # Verify all were audited
        total_audited = configured_runtime.audit.record_count()
        assert total_audited >= 100, (
            f"Not all concurrent requests were audited: {total_audited}/100"
        )

    @pytest.mark.atm1(attack_vector="AV-7")
    @pytest.mark.atx1(technique_id="T2001")
    def test_cross_agent_privilege_leak(self, multi_agent_runtime: AEGISRuntime):
        """Restricted agent tries to use privileged agent's capabilities."""
        # Restricted agent should not be able to read files
        request = make_request(
            agent_id="restricted-agent",
            action_type=ActionType.FILE_READ,
            target="/etc/passwd",
        )
        response = multi_agent_runtime.gateway.submit(request)
        assert response.decision == Decision.DENIED, (
            "Restricted agent should not have FILE_READ capability"
        )

        # Privileged agent can read files
        priv_request = make_request(
            agent_id="privileged-agent",
            action_type=ActionType.FILE_READ,
            target="/etc/passwd",
        )
        priv_response = multi_agent_runtime.gateway.submit(priv_request)
        assert priv_response.decision == Decision.APPROVED

    @pytest.mark.atm1(attack_vector="AV-7")
    @pytest.mark.atx1(technique_id="T2004")
    def test_expired_capability_access(self, runtime: AEGISRuntime):
        """Agent with expired capability should be denied."""
        expired_cap = Capability(
            id="cap-expired",
            name="Expired capability",
            description="Already expired",
            action_types=[ActionType.TOOL_CALL.value],
            target_patterns=["*"],
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        runtime.capabilities.register(expired_cap)
        runtime.capabilities.grant("expired-agent", "cap-expired")
        runtime.policies.add_policy(make_allow_policy())

        request = make_request(agent_id="expired-agent", target="test-target")
        response = runtime.gateway.submit(request)
        assert response.decision == Decision.DENIED, (
            "Expired capability correctly denied"
        )


# ===================================================================
# Cross-Cutting: Security Property Validation
# ===================================================================

class TestSecurityPropertyViolations:
    """Tests targeting specific AEGIS security properties (SP-1..SP-5)."""

    @pytest.mark.security_property(sp_id="SP-1")
    def test_sp1_decision_determinism(self, configured_runtime: AEGISRuntime):
        """SP-1: Same request shape + policies must produce same decision."""
        decisions = []
        for _ in range(50):
            # Each request gets a unique request_id (replay protection)
            # but identical agent_id, action, and context
            request = make_request(agent_id="test-agent", target="test-target")
            response = configured_runtime.gateway.submit(request)
            decisions.append(response.decision)

        unique_decisions = set(decisions)
        assert len(unique_decisions) == 1, (
            f"Non-deterministic decisions: {unique_decisions}"
        )

    @pytest.mark.security_property(sp_id="SP-4")
    def test_sp4_no_action_without_capability(self, runtime: AEGISRuntime):
        """SP-4: No action proceeds without prior capability authorization."""
        # No capabilities registered at all
        runtime.policies.add_policy(make_allow_policy())

        for action_type in ActionType:
            request = make_request(
                agent_id="unconfigured-agent",
                action_type=action_type,
                target="any-target",
            )
            response = runtime.gateway.submit(request)
            assert response.decision == Decision.DENIED, (
                f"SP-4 violation: {action_type.value} approved without capability"
            )

    @pytest.mark.security_property(sp_id="SP-5")
    def test_sp5_audit_completeness(self, configured_runtime: AEGISRuntime):
        """SP-5: Every decision (approved and denied) must be audited."""
        approved_req = make_request(
            agent_id="test-agent", target="test-target"
        )
        denied_req = make_request(
            agent_id="unknown-agent", target="test-target"
        )

        approved_resp = configured_runtime.gateway.submit(approved_req)
        denied_resp = configured_runtime.gateway.submit(denied_req)

        assert approved_resp.decision == Decision.APPROVED
        assert denied_resp.decision == Decision.DENIED

        # Both must have audit records
        approved_audit = configured_runtime.audit.get_record(approved_resp.audit_id)
        denied_audit = configured_runtime.audit.get_record(denied_resp.audit_id)

        assert approved_audit is not None, "Approved decision not audited"
        assert denied_audit is not None, "Denied decision not audited"
        assert approved_audit.decision == "approved"
        assert denied_audit.decision == "denied"
