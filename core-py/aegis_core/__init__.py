"""AEGIS™ - Architectural Enforcement & Governance of Intelligent Systems.

A governance runtime for AI systems that enforces deterministic control
over AI-generated actions before they interact with infrastructure.

Core flow
---------
1. AI systems propose actions via the AGP protocol.
2. The :class:`GovernanceGateway` validates and forwards the request.
3. The :class:`DecisionEngine` evaluates capability and policy rules.
4. Only ``Decision.APPROVED`` responses permit action execution.
5. Every decision is permanently recorded in the :class:`AuditSystem`.

Quick-start
-----------
Use :class:`AEGISRuntime` for the simplest integration::

    from aegis_core import AEGISRuntime

    runtime = AEGISRuntime()
    # … configure capabilities and policies …
    proxy = runtime.create_tool_proxy("my-agent", "session-1")
    proxy.call("my_tool", arg="value")
"""

from . import errors
from .audit import AuditRecord, AuditSystem
from .capability_registry import Capability, CapabilityRegistry
from .decision_engine import DecisionEngine
from .exceptions import (
    AEGISAuditError,
    AEGISCapabilityError,
    AEGISError,
    AEGISPolicyError,
    AEGISValidationError,
)
from .gateway import GovernanceGateway
from .policy_engine import (
    Policy,
    PolicyCondition,
    PolicyEffect,
    PolicyEngine,
    PolicyEvaluation,
    PolicyResult,
)
from .protocol import (
    ActionType,
    AGPAction,
    AGPContext,
    AGPRequest,
    AGPResponse,
    Decision,
)
from .runtime import AEGISRuntime
from .tool_proxy import ToolProxy

__all__ = [
    "AEGISAuditError",
    "AEGISCapabilityError",
    # Exceptions
    "AEGISError",
    # Error catalog
    "errors",
    "AEGISPolicyError",
    # Runtime facade
    "AEGISRuntime",
    "AEGISValidationError",
    # Protocol
    "AGPAction",
    "AGPContext",
    "AGPRequest",
    "AGPResponse",
    "ActionType",
    # Audit
    "AuditRecord",
    "AuditSystem",
    # Capability Registry
    "Capability",
    "CapabilityRegistry",
    "Decision",
    # Decision Engine
    "DecisionEngine",
    # Gateway
    "GovernanceGateway",
    # Policy Engine
    "Policy",
    "PolicyCondition",
    "PolicyEffect",
    "PolicyEngine",
    "PolicyEvaluation",
    "PolicyResult",
    # Tool Proxy
    "ToolProxy",
]
