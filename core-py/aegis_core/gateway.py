"""
aegis_core.gateway — Governance Gateway

The governance gateway is the primary entry point for the AEGIS enforcement
engine. It implements the AGP-1 protocol message exchange:

  1. Receives an ACTION_PROPOSE message from a governed AI system. This message
     describes an action the system intends to take (e.g., "send email",
     "access database", "generate content").

  2. Dispatches the proposal through the enforcement pipeline:
     - Capability verification (does the system have permission?)
     - Policy evaluation (do governance policies allow this action?)
     - Risk scoring (what is the composite risk level?)

  3. Returns a DECISION_RESPONSE message containing:
     - verdict: "approve", "deny", or "escalate"
     - risk_score: numeric risk assessment
     - policy_citations: which policies influenced the decision
     - conditions: any constraints on approved actions

Protocol Messages (AGP-1):
    ACTION_PROPOSE → Gateway → Pipeline → DECISION_RESPONSE

This module uses only the Python standard library.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class Verdict(Enum):
    """Possible governance decision outcomes."""
    APPROVE = "approve"
    DENY = "deny"
    ESCALATE = "escalate"


@dataclass
class ActionProposal:
    """
    Represents an ACTION_PROPOSE message in the AGP-1 protocol.

    A governed AI system sends this to request permission for an action.
    """
    system_id: str
    action_type: str
    parameters: dict[str, Any] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class DecisionResponse:
    """
    Represents a DECISION_RESPONSE message in the AGP-1 protocol.

    The gateway returns this after evaluating a proposed action.
    """
    verdict: Verdict
    risk_score: float = 0.0
    policy_citations: list[str] = field(default_factory=list)
    conditions: list[str] = field(default_factory=list)
    reasoning: str = ""


class GovernanceGateway:
    """
    Primary entry point for governance enforcement.

    Receives ACTION_PROPOSE messages, dispatches them through the
    enforcement pipeline, and returns DECISION_RESPONSE messages.
    """

    def evaluate(self, proposal: ActionProposal) -> DecisionResponse:
        """
        Evaluate a proposed action against governance policies.

        Args:
            proposal: The ACTION_PROPOSE message to evaluate.

        Returns:
            A DECISION_RESPONSE with the governance verdict.
        """
        # TODO: Wire up capability, policy, and risk engines
        logger.info(
            "Evaluating proposal: system=%s action=%s",
            proposal.system_id,
            proposal.action_type,
        )
        return DecisionResponse(
            verdict=Verdict.ESCALATE,
            reasoning="Enforcement pipeline not yet implemented — escalating by default.",
        )
