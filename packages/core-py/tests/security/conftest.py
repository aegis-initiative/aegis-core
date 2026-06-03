"""Shared fixtures for red/blue team security tests.

Provides pre-configured AEGIS runtimes, helper factories,
and pytest markers for ATM-1/ATX-1 traceability.
"""

from __future__ import annotations

import pytest

from aegis_core import AEGISRuntime
from aegis_core.capability_registry import Capability
from aegis_core.policy_engine import Policy, PolicyCondition, PolicyEffect
from aegis_core.protocol import ActionType, AGPAction, AGPContext, AGPRequest

# ---------------------------------------------------------------------------
# Pytest markers for threat traceability
# ---------------------------------------------------------------------------


def atm1(attack_vector: str, description: str = ""):
    """Marker linking a test to an ATM-1 attack vector (AV-1..AV-7)."""
    return pytest.mark.atm1(attack_vector=attack_vector, description=description)


def atx1(technique_id: str, description: str = ""):
    """Marker linking a test to an ATX-1 technique (T1001..T10004)."""
    return pytest.mark.atx1(technique_id=technique_id, description=description)


def security_property(sp_id: str, description: str = ""):
    """Marker linking a test to a security property (SP-1..SP-5)."""
    return pytest.mark.security_property(sp_id=sp_id, description=description)


# ---------------------------------------------------------------------------
# Request factory helpers
# ---------------------------------------------------------------------------


def make_request(
    agent_id: str = "test-agent",
    action_type: ActionType = ActionType.TOOL_CALL,
    target: str = "test-target",
    session_id: str = "test-session",
    parameters: dict | None = None,
    metadata: dict | None = None,
) -> AGPRequest:
    """Build an AGPRequest with sensible defaults for testing."""
    return AGPRequest(
        agent_id=agent_id,
        action=AGPAction(
            type=action_type,
            target=target,
            parameters=parameters or {},
        ),
        context=AGPContext(
            session_id=session_id,
            metadata=metadata or {},
        ),
    )


def make_capability(
    cap_id: str = "cap-test",
    name: str = "Test Capability",
    action_types: list[str] | None = None,
    target_patterns: list[str] | None = None,
    **kwargs,
) -> Capability:
    """Build a Capability with sensible defaults."""
    return Capability(
        id=cap_id,
        name=name,
        description=f"Test capability: {name}",
        action_types=action_types or [ActionType.TOOL_CALL.value],
        target_patterns=target_patterns or ["*"],
        **kwargs,
    )


def make_allow_policy(
    policy_id: str = "pol-allow",
    name: str = "Allow Policy",
    conditions: list[PolicyCondition] | None = None,
    priority: int = 200,
) -> Policy:
    """Build an ALLOW policy."""
    return Policy(
        id=policy_id,
        name=name,
        description=f"Allow policy: {name}",
        effect=PolicyEffect.ALLOW,
        conditions=conditions or [],
        priority=priority,
    )


def make_deny_policy(
    policy_id: str = "pol-deny",
    name: str = "Deny Policy",
    conditions: list[PolicyCondition] | None = None,
    priority: int = 100,
) -> Policy:
    """Build a DENY policy."""
    return Policy(
        id=policy_id,
        name=name,
        description=f"Deny policy: {name}",
        effect=PolicyEffect.DENY,
        conditions=conditions or [],
        priority=priority,
    )


# ---------------------------------------------------------------------------
# Runtime fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def runtime() -> AEGISRuntime:
    """A fresh, unconfigured runtime (default-deny)."""
    with AEGISRuntime() as rt:
        yield rt


@pytest.fixture
def configured_runtime() -> AEGISRuntime:
    """A runtime with a basic capability + allow policy for test-agent."""
    with AEGISRuntime() as rt:
        cap = make_capability(
            cap_id="cap-basic",
            name="Basic tool access",
            action_types=[ActionType.TOOL_CALL.value],
            target_patterns=["test-*"],
        )
        rt.capabilities.register(cap)
        rt.capabilities.grant("test-agent", "cap-basic")

        pol = make_allow_policy(
            policy_id="pol-basic-allow",
            name="Allow basic tool calls",
        )
        rt.policies.add_policy(pol)
        yield rt


@pytest.fixture
def multi_agent_runtime() -> AEGISRuntime:
    """A runtime with multiple agents at different privilege levels."""
    with AEGISRuntime() as rt:
        # Privileged agent — can do file reads and tool calls
        cap_priv = make_capability(
            cap_id="cap-privileged",
            name="Privileged access",
            action_types=[ActionType.TOOL_CALL.value, ActionType.FILE_READ.value],
            target_patterns=["*"],
        )
        rt.capabilities.register(cap_priv)
        rt.capabilities.grant("privileged-agent", "cap-privileged")

        # Restricted agent — tool calls to test-* only
        cap_restricted = make_capability(
            cap_id="cap-restricted",
            name="Restricted access",
            action_types=[ActionType.TOOL_CALL.value],
            target_patterns=["test-*"],
        )
        rt.capabilities.register(cap_restricted)
        rt.capabilities.grant("restricted-agent", "cap-restricted")

        # Allow policy
        pol = make_allow_policy(policy_id="pol-allow-all", name="Allow all")
        rt.policies.add_policy(pol)
        yield rt
