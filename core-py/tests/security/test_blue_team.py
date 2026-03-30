"""Blue Team Tests — AEGIS Defensive Validation.

Validates that AEGIS security controls are effective and that
red team findings have been properly remediated.

Organized by ATM-1 control categories:
- PC: Preventive Controls
- DC: Detective Controls
- RC: Responsive Controls

Each test validates a specific control and links to the red team
finding it remediates.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from aegis_core import AEGISRuntime
from aegis_core.capability_registry import Capability
from aegis_core.exceptions import (
    AEGISCapabilityError,
    AEGISPolicyError,
    AEGISValidationError,
)
from aegis_core.policy_engine import Policy, PolicyCondition, PolicyEffect
from aegis_core.protocol import (
    AGPAction,
    AGPContext,
    AGPRequest,
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
# PC-4: Input Validation & Sanitization
# ===================================================================

class TestInputValidation:
    """Validates gateway input validation controls (PC-4)."""

    def test_empty_agent_id_rejected(self, runtime: AEGISRuntime):
        """Gateway rejects empty agent_id."""
        request = make_request(agent_id="valid-agent", target="test-target")
        request.agent_id = ""
        with pytest.raises(AEGISValidationError, match="agent_id"):
            runtime.gateway.submit(request)

    def test_whitespace_agent_id_rejected(self, runtime: AEGISRuntime):
        """Gateway rejects whitespace-only agent_id."""
        request = make_request(agent_id="valid-agent", target="test-target")
        request.agent_id = "   "
        with pytest.raises(AEGISValidationError, match="agent_id"):
            runtime.gateway.submit(request)

    def test_special_chars_agent_id_rejected(self, runtime: AEGISRuntime):
        """Gateway rejects agent_id with special characters."""
        invalid_ids = [
            "agent;DROP TABLE",
            "agent<script>",
            "agent\x00null",
            "agent/../../../etc",
            "agent\ninjection",
        ]
        for agent_id in invalid_ids:
            request = make_request(agent_id="placeholder", target="test-target")
            request.agent_id = agent_id
            with pytest.raises(AEGISValidationError):
                runtime.gateway.submit(request)

    def test_oversized_agent_id_rejected(self, runtime: AEGISRuntime):
        """Gateway rejects agent_id exceeding max length (256)."""
        request = make_request(agent_id="a" * 257, target="test-target")
        with pytest.raises(AEGISValidationError, match="maximum length"):
            runtime.gateway.submit(request)

    def test_empty_target_rejected(self, runtime: AEGISRuntime):
        """Gateway rejects empty action target."""
        request = make_request(agent_id="test-agent", target="x")
        request.action.target = ""
        with pytest.raises(AEGISValidationError, match="target"):
            runtime.gateway.submit(request)

    def test_oversized_target_rejected(self, runtime: AEGISRuntime):
        """Gateway rejects target exceeding max length (1024)."""
        request = make_request(agent_id="test-agent", target="t" * 1025)
        with pytest.raises(AEGISValidationError, match="maximum length"):
            runtime.gateway.submit(request)

    def test_empty_session_id_rejected(self, runtime: AEGISRuntime):
        """Gateway rejects empty session_id."""
        request = make_request(
            agent_id="test-agent", target="test-target", session_id="x"
        )
        request.context.session_id = ""
        with pytest.raises(AEGISValidationError, match="session_id"):
            runtime.gateway.submit(request)

    def test_none_request_rejected(self, runtime: AEGISRuntime):
        """Gateway rejects None request."""
        with pytest.raises(AEGISValidationError):
            runtime.gateway.submit(None)

    def test_none_action_rejected(self, runtime: AEGISRuntime):
        """Gateway rejects request with None action."""
        request = make_request(agent_id="test-agent", target="test-target")
        request.action = None
        with pytest.raises(AEGISValidationError, match="action"):
            runtime.gateway.submit(request)

    def test_none_parameters_rejected(self, runtime: AEGISRuntime):
        """Gateway rejects request with None parameters."""
        request = make_request(agent_id="test-agent", target="test-target")
        request.action.parameters = None
        with pytest.raises(AEGISValidationError, match="parameters"):
            runtime.gateway.submit(request)


# ===================================================================
# SP-4: Capability Authorization Binding (Defense-in-Depth Layer 1)
# ===================================================================

class TestCapabilityControls:
    """Validates capability-based access control (SP-4)."""

    def test_default_deny_no_capabilities(self, runtime: AEGISRuntime):
        """Unconfigured runtime denies all actions (default-deny)."""
        for action_type in ActionType:
            request = make_request(
                agent_id="any-agent",
                action_type=action_type,
                target="any-target",
            )
            response = runtime.gateway.submit(request)
            assert response.decision == Decision.DENIED

    def test_capability_scope_enforcement(self, runtime: AEGISRuntime):
        """Capability only grants access to declared action types and targets."""
        cap = make_capability(
            cap_id="cap-scoped",
            action_types=[ActionType.FILE_READ.value],
            target_patterns=["/docs/*"],
        )
        runtime.capabilities.register(cap)
        runtime.capabilities.grant("scoped-agent", "cap-scoped")
        runtime.policies.add_policy(make_allow_policy())

        # Allowed: FILE_READ on /docs/readme.md
        allowed_req = make_request(
            agent_id="scoped-agent",
            action_type=ActionType.FILE_READ,
            target="/docs/readme.md",
        )
        assert runtime.gateway.submit(allowed_req).decision == Decision.APPROVED

        # Denied: FILE_WRITE on /docs/readme.md (wrong action type)
        write_req = make_request(
            agent_id="scoped-agent",
            action_type=ActionType.FILE_WRITE,
            target="/docs/readme.md",
        )
        assert runtime.gateway.submit(write_req).decision == Decision.DENIED

        # Denied: FILE_READ on /etc/passwd (wrong target)
        wrong_target_req = make_request(
            agent_id="scoped-agent",
            action_type=ActionType.FILE_READ,
            target="/etc/passwd",
        )
        assert runtime.gateway.submit(wrong_target_req).decision == Decision.DENIED

    def test_capability_expiry_enforcement(self, runtime: AEGISRuntime):
        """Expired capabilities are not honored."""
        expired_cap = Capability(
            id="cap-expired",
            name="Expired",
            description="Already expired",
            action_types=[ActionType.TOOL_CALL.value],
            target_patterns=["*"],
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        runtime.capabilities.register(expired_cap)
        runtime.capabilities.grant("agent", "cap-expired")
        runtime.policies.add_policy(make_allow_policy())

        request = make_request(agent_id="agent", target="test-target")
        assert runtime.gateway.submit(request).decision == Decision.DENIED

    def test_capability_revocation_immediate(self, runtime: AEGISRuntime):
        """Revoked capabilities immediately deny access."""
        cap = make_capability(cap_id="cap-revocable")
        runtime.capabilities.register(cap)
        runtime.capabilities.grant("agent", "cap-revocable")
        runtime.policies.add_policy(make_allow_policy())

        request1 = make_request(agent_id="agent", target="test-target")
        assert runtime.gateway.submit(request1).decision == Decision.APPROVED

        # Revoke
        runtime.capabilities.revoke("agent", "cap-revocable")
        request2 = make_request(agent_id="agent", target="test-target")
        assert runtime.gateway.submit(request2).decision == Decision.DENIED

    def test_unknown_capability_grant_rejected(self, runtime: AEGISRuntime):
        """Cannot grant a capability that doesn't exist in the registry."""
        with pytest.raises(AEGISCapabilityError):
            runtime.capabilities.grant("agent", "nonexistent-capability")

    def test_agent_isolation(self, multi_agent_runtime: AEGISRuntime):
        """One agent's capabilities don't leak to another."""
        # Restricted agent cannot read files
        request = make_request(
            agent_id="restricted-agent",
            action_type=ActionType.FILE_READ,
            target="/etc/passwd",
        )
        assert multi_agent_runtime.gateway.submit(request).decision == Decision.DENIED

        # Privileged agent can
        priv_req = make_request(
            agent_id="privileged-agent",
            action_type=ActionType.FILE_READ,
            target="/etc/passwd",
        )
        assert multi_agent_runtime.gateway.submit(priv_req).decision == Decision.APPROVED


# ===================================================================
# Policy Evaluation Controls (Defense-in-Depth Layer 2)
# ===================================================================

class TestPolicyControls:
    """Validates deterministic policy evaluation."""

    def test_deny_takes_precedence_over_allow(self, runtime: AEGISRuntime):
        """Deny policies always override allow policies regardless of priority."""
        cap = make_capability()
        runtime.capabilities.register(cap)
        runtime.capabilities.grant("test-agent", "cap-test")

        # Allow at priority 0 (highest)
        runtime.policies.add_policy(make_allow_policy(priority=0))
        # Deny at priority 999 (lowest)
        runtime.policies.add_policy(
            make_deny_policy(
                policy_id="pol-deny-low-priority",
                priority=999,
                conditions=[
                    PolicyCondition(
                        evaluate=lambda r: True,
                        description="Match all",
                    )
                ],
            )
        )

        request = make_request()
        response = runtime.gateway.submit(request)
        assert response.decision == Decision.DENIED, (
            "Deny must take precedence regardless of priority"
        )

    def test_default_deny_when_no_policies_match(self, runtime: AEGISRuntime):
        """Default-deny when no policies match (even with capabilities)."""
        cap = make_capability()
        runtime.capabilities.register(cap)
        runtime.capabilities.grant("test-agent", "cap-test")

        # Add a conditional allow that won't match
        runtime.policies.add_policy(
            make_allow_policy(
                conditions=[
                    PolicyCondition(
                        evaluate=lambda r: r.agent_id == "other-agent",
                        description="Only other-agent",
                    )
                ]
            )
        )

        request = make_request()
        response = runtime.gateway.submit(request)
        assert response.decision == Decision.DENIED

    def test_disabled_policy_not_evaluated(self, runtime: AEGISRuntime):
        """Disabled policies are skipped during evaluation."""
        cap = make_capability()
        runtime.capabilities.register(cap)
        runtime.capabilities.grant("test-agent", "cap-test")

        allow_policy = make_allow_policy()
        allow_policy.enabled = False
        runtime.policies.add_policy(allow_policy)

        request = make_request()
        response = runtime.gateway.submit(request)
        assert response.decision == Decision.DENIED, (
            "Disabled allow policy should not grant access"
        )

    def test_policy_validation_rejects_invalid(self, runtime: AEGISRuntime):
        """PolicyEngine rejects structurally invalid policies."""
        with pytest.raises(AEGISPolicyError):
            runtime.policies.add_policy(
                Policy(
                    id="",  # Empty ID
                    name="Bad policy",
                    description="Invalid",
                    effect=PolicyEffect.ALLOW,
                    conditions=[],
                )
            )

    def test_duplicate_policy_id_rejected(self, runtime: AEGISRuntime):
        """Cannot register two policies with the same ID."""
        runtime.policies.add_policy(make_allow_policy(policy_id="pol-unique"))
        with pytest.raises(ValueError, match="already registered"):
            runtime.policies.add_policy(make_allow_policy(policy_id="pol-unique"))

    def test_escalate_precedence(self, runtime: AEGISRuntime):
        """ESCALATE takes precedence over ALLOW."""
        cap = make_capability()
        runtime.capabilities.register(cap)
        runtime.capabilities.grant("test-agent", "cap-test")

        runtime.policies.add_policy(make_allow_policy(priority=200))
        runtime.policies.add_policy(
            Policy(
                id="pol-escalate",
                name="Escalate",
                description="Escalate for review",
                effect=PolicyEffect.ESCALATE,
                conditions=[],
                priority=150,
            )
        )

        request = make_request()
        response = runtime.gateway.submit(request)
        assert response.decision == Decision.ESCALATE


# ===================================================================
# SP-5: Audit Completeness (Defense-in-Depth Layer 3)
# ===================================================================

class TestAuditControls:
    """Validates audit trail completeness and integrity (SP-5)."""

    def test_approved_decisions_audited(self, configured_runtime: AEGISRuntime):
        """Every approved decision creates an audit record."""
        request = make_request(agent_id="test-agent", target="test-target")
        response = configured_runtime.gateway.submit(request)
        assert response.decision == Decision.APPROVED

        record = configured_runtime.audit.get_record(response.audit_id)
        assert record is not None
        assert record.decision == "approved"
        assert record.agent_id == "test-agent"

    def test_denied_decisions_audited(self, runtime: AEGISRuntime):
        """Every denied decision creates an audit record."""
        request = make_request(agent_id="denied-agent", target="test-target")
        response = runtime.gateway.submit(request)
        assert response.decision == Decision.DENIED

        record = runtime.audit.get_record(response.audit_id)
        assert record is not None
        assert record.decision == "denied"

    def test_audit_records_immutable_via_api(self, configured_runtime: AEGISRuntime):
        """AuditRecord is a frozen dataclass — cannot be modified."""
        request = make_request(agent_id="test-agent", target="test-target")
        response = configured_runtime.gateway.submit(request)
        record = configured_runtime.audit.get_record(response.audit_id)

        with pytest.raises(AttributeError):
            record.decision = "tampered"

    def test_audit_contains_full_decision_chain(self, configured_runtime: AEGISRuntime):
        """Audit record includes request details, decision, and policy trace."""
        request = make_request(agent_id="test-agent", target="test-target")
        response = configured_runtime.gateway.submit(request)
        record = configured_runtime.audit.get_record(response.audit_id)

        assert record.request_id == request.request_id
        assert record.agent_id == "test-agent"
        assert record.action_type == ActionType.TOOL_CALL.value
        assert record.action_target == "test-target"
        assert record.session_id == "test-session"
        assert record.timestamp is not None

    def test_audit_queryable_by_agent(self, configured_runtime: AEGISRuntime):
        """Audit records can be queried by agent_id."""
        for i in range(5):
            request = make_request(
                agent_id="test-agent",
                target="test-target",
                session_id=f"session-{i}",
            )
            configured_runtime.gateway.submit(request)

        history = configured_runtime.audit.get_agent_history("test-agent")
        assert len(history) == 5
        assert all(r.agent_id == "test-agent" for r in history)

    def test_audit_queryable_by_session(self, configured_runtime: AEGISRuntime):
        """Audit records can be queried by session_id."""
        for i in range(3):
            request = make_request(
                agent_id="test-agent",
                target=f"target-{i}",
                session_id="tracked-session",
            )
            configured_runtime.gateway.submit(request)

        history = configured_runtime.audit.get_session_history("tracked-session")
        assert len(history) == 3
        assert all(r.session_id == "tracked-session" for r in history)

    def test_concurrent_audit_integrity(self, configured_runtime: AEGISRuntime):
        """Concurrent requests all produce valid audit records."""
        results = []

        def submit(i: int):
            request = make_request(
                agent_id="test-agent",
                target="test-target",
                session_id=f"concurrent-{i}",
            )
            response = configured_runtime.gateway.submit(request)
            results.append(response)

        threads = [threading.Thread(target=submit, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10.0)

        assert len(results) == 20
        # Every response has a valid audit_id and the record exists
        for response in results:
            record = configured_runtime.audit.get_record(response.audit_id)
            assert record is not None, (
                f"Missing audit record for audit_id={response.audit_id}"
            )


# ===================================================================
# Tool Proxy Controls
# ===================================================================

class TestToolProxyControls:
    """Validates governance interception at the tool proxy layer."""

    def test_unregistered_tool_rejected(self, configured_runtime: AEGISRuntime):
        """Calling an unregistered tool raises ValueError."""
        proxy = configured_runtime.create_tool_proxy("test-agent", "sess")
        with pytest.raises(ValueError, match="not registered"):
            proxy.call("nonexistent_tool")

    def test_denied_tool_not_executed(self, runtime: AEGISRuntime):
        """Denied tool calls never execute the underlying function."""
        call_count = 0

        def tracked_tool(**kwargs):
            nonlocal call_count
            call_count += 1
            return "executed"

        proxy = runtime.create_tool_proxy("no-cap-agent", "sess")
        proxy.register_tool("dangerous", fn=tracked_tool, target="dangerous-target")

        with pytest.raises(PermissionError):
            proxy.call("dangerous")

        assert call_count == 0, "Tool was executed despite governance denial"

    def test_approved_tool_executed(self, configured_runtime: AEGISRuntime):
        """Approved tool calls execute the function and return results."""
        proxy = configured_runtime.create_tool_proxy("test-agent", "sess")
        proxy.register_tool(
            "safe_tool",
            fn=lambda **kw: "result",
            target="test-target",
        )

        result = proxy.call("safe_tool")
        assert result == "result"
