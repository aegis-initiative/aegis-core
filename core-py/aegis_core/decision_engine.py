"""Decision Engine.

The Decision Engine is the authoritative evaluator of every AGP request.
It orchestrates the two-stage governance pipeline:

1. **Capability check** - Does the agent hold a capability that covers
   this action type and target?  If not, deny immediately.
2. **Policy evaluation** - Do the configured policies allow the action?

Every decision, regardless of outcome, is committed to the :class:`~aegis.audit.AuditSystem`
before the :class:`~aegis.protocol.AGPResponse` is returned.  This ensures
full auditability even for denied requests.

The Decision Engine also provides telemetry hooks and metrics for
instrumentation and monitoring of governance decisions.

.. note::

   External callers should use :meth:`GovernanceGateway.submit` rather
   than calling ``_evaluate`` directly.  The gateway performs protocol-level
   validation (format, replay, size, metacharacter, sensitive-path checks).
   The engine performs independent *structural* validation as a
   defense-in-depth measure (RT-001 / T1001, T9001).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any

from .audit import AuditSystem
from .capability_registry import CapabilityRegistry
from .exceptions import AEGISValidationError
from .policy_engine import PolicyEngine
from .protocol import ActionType, AGPRequest, AGPResponse, Decision
from .risk import RiskEngine


@dataclass
class DecisionMetrics:
    """Aggregated metrics about governance decisions.

    Parameters
    ----------
    total_decisions : int
        Total number of decisions evaluated.
    approved_count : int
        Number of decisions that were APPROVED.
    denied_count : int
        Number of decisions that were DENIED.
    deferred_count : int
        Number of decisions that were ESCALATE.
    capability_denials : int
        Number of decisions denied in stage 1 (capability check).
    policy_denials : int
        Number of decisions denied in stage 2 (policy evaluation).
    total_latency_ms : float
        Cumulative latency of all decisions in milliseconds.
    avg_latency_ms : float
        Average decision latency in milliseconds.
    """

    total_decisions: int = 0
    approved_count: int = 0
    denied_count: int = 0
    deferred_count: int = 0
    capability_denials: int = 0
    policy_denials: int = 0
    total_latency_ms: float = 0.0
    avg_latency_ms: float = 0.0


class DecisionEngine:
    """Evaluates :class:`~aegis.protocol.AGPRequest` objects and returns
    :class:`~aegis.protocol.AGPResponse` objects.

    Provides comprehensive telemetry hooks and metrics collection for
    monitoring and instrumentation of governance decisions.

    .. warning::

       Use :meth:`GovernanceGateway.submit` as the public entry point.
       ``_evaluate`` is an internal method guarded by independent
       structural validation, but it does **not** perform protocol-level
       checks (replay, size limits, metacharacters, sensitive paths).

    Parameters
    ----------
    capability_registry : CapabilityRegistry
        Registry used for the capability check (stage 1).
    policy_engine : PolicyEngine
        Engine used for policy evaluation (stage 2).
    audit_system : AuditSystem
        Audit system where every decision is recorded.
    risk_engine : RiskEngine, optional
        Risk engine for proportionality assessment (stage 3).
        If None, a default RiskEngine is created using the audit system.
    """

    def __init__(
        self,
        capability_registry: CapabilityRegistry,
        policy_engine: PolicyEngine,
        audit_system: AuditSystem,
        risk_engine: RiskEngine | None = None,
    ) -> None:
        self._capabilities = capability_registry
        self._policies = policy_engine
        self._audit = audit_system
        self._risk = risk_engine or RiskEngine(audit_system=audit_system)

        # RT-003 / T2001, RT-007 / T8002: Unified evaluation lock ensures
        # all three stages are atomic - prevents TOCTOU.
        self._eval_lock = threading.Lock()

        # H-2: Thread-safe metrics
        self._metrics_lock = threading.Lock()
        self._metrics = DecisionMetrics()

    # ------------------------------------------------------------------
    # Structural validation (defense-in-depth, RT-001)
    # ------------------------------------------------------------------

    def _validate_request(self, request: AGPRequest) -> None:
        """Independent structural validation at the engine layer.

        This is a defense-in-depth check.  The gateway performs full
        protocol-level validation; the engine independently verifies
        structural integrity so that even direct callers cannot submit
        fundamentally broken requests.

        Checks:
        - Request is not None
        - Request has action, context, agent_id, and request_id
        - Action has a valid ActionType and non-empty target
        - Context has a non-empty session_id

        Parameters
        ----------
        request : AGPRequest
            The request to validate structurally.

        Raises
        ------
        AEGISValidationError
            If the request fails structural validation.
        """
        if request is None:
            raise AEGISValidationError(
                "Engine received None request",
                error_code="ENGINE_NULL_REQUEST",
            )

        if not hasattr(request, "agent_id") or not request.agent_id:
            raise AEGISValidationError(
                "Engine received request without agent_id",
                error_code="ENGINE_MISSING_AGENT_ID",
            )

        if not hasattr(request, "request_id") or not request.request_id:
            raise AEGISValidationError(
                "Engine received request without request_id",
                error_code="ENGINE_MISSING_REQUEST_ID",
            )

        if request.action is None:
            raise AEGISValidationError(
                "Engine received request with None action",
                error_code="ENGINE_NULL_ACTION",
            )

        if not isinstance(request.action.type, ActionType):
            raise AEGISValidationError(
                f"Engine received invalid action type: {request.action.type!r}",
                error_code="ENGINE_INVALID_ACTION_TYPE",
            )

        if not request.action.target:
            raise AEGISValidationError(
                "Engine received request with empty action target",
                error_code="ENGINE_EMPTY_TARGET",
            )

        if request.context is None:
            raise AEGISValidationError(
                "Engine received request with None context",
                error_code="ENGINE_NULL_CONTEXT",
            )

        if not request.context.session_id:
            raise AEGISValidationError(
                "Engine received request with empty session_id",
                error_code="ENGINE_EMPTY_SESSION_ID",
            )

    # ------------------------------------------------------------------
    # Evaluation pipeline
    # ------------------------------------------------------------------

    def _evaluate(self, request: AGPRequest) -> AGPResponse:
        """Run the full governance pipeline for *request*.

        This is an internal method.  External callers should use
        :meth:`GovernanceGateway.submit`, which adds protocol-level
        validation (replay, size, metacharacters, sensitive paths)
        on top of the structural validation performed here.

        Returns an :class:`~aegis.protocol.AGPResponse` whose
        :attr:`~aegis.protocol.AGPResponse.decision` field is the
        authoritative governance decision.

        The method is intentionally synchronous and free of side-effects
        beyond writing to the audit log and recording metrics, making it
        straightforward to test deterministically.

        Parameters
        ----------
        request : AGPRequest
            The governance request to evaluate.

        Returns
        -------
        AGPResponse
            The governance decision response.

        Raises
        ------
        AEGISValidationError
            If the request fails structural validation.
        """
        # Defense-in-depth: validate independently of gateway (RT-001)
        self._validate_request(request)

        start_time = time.perf_counter()

        action_type: str = (
            request.action.type.value
            if hasattr(request.action.type, "value")
            else str(request.action.type)
        )

        # RT-003 / RT-007: Hold unified lock across both stages to prevent
        # TOCTOU - capabilities and policies cannot change mid-evaluation.
        with self._eval_lock:
            # --------------------------------------------------------------
            # Stage 1: Capability check
            # --------------------------------------------------------------
            has_capability = self._capabilities.has_capability_for_action(
                request.agent_id,
                action_type,
                request.action.target,
            )

            if not has_capability:
                decision = Decision.DENIED
                # BT-AUDIT-006: Sanitize — don't leak full target details
                reason = (
                    f"Agent lacks a capability covering "
                    f"action '{action_type}' on the requested target."
                )
                policy_evaluations: list[dict[str, Any]] = []
                # Telemetry: capability denial
                self._metrics.capability_denials += 1
            else:
                # ----------------------------------------------------------
                # Stage 2: Policy evaluation
                # ----------------------------------------------------------
                policy_result = self._policies.evaluate(request)
                decision = policy_result.decision
                reason = policy_result.reason
                policy_evaluations = [
                    {
                        "policy_id": ev.policy_id,
                        "policy_name": ev.policy_name,
                        "effect": ev.effect,
                        "matched": ev.matched,
                    }
                    for ev in policy_result.evaluations
                ]

                # Telemetry: policy-stage denial
                if decision == Decision.DENIED:
                    self._metrics.policy_denials += 1

            # --------------------------------------------------------------
            # Stage 3: Risk assessment (inside lock — H-1 fix)
            # --------------------------------------------------------------
            risk_assessment = self._risk.assess(
                action_type=action_type,
                target=request.action.target,
                agent_id=request.agent_id,
                parameters=request.action.parameters,
            )

            # Proportionality override: if policy approved but risk is
            # too high, escalate the decision.
            if decision == Decision.APPROVED:
                if (
                    risk_assessment.composite_score
                    >= self._risk.escalation_threshold
                ):
                    decision = Decision.ESCALATE
                    reason = (
                        f"Risk score {risk_assessment.composite_score}/10.0 "
                        f"exceeds escalation threshold "
                        f"({self._risk.escalation_threshold}). "
                        f"{risk_assessment.explanation}"
                    )
                elif (
                    risk_assessment.composite_score
                    >= self._risk.require_confirmation_threshold
                ):
                    decision = Decision.REQUIRE_CONFIRMATION
                    reason = (
                        f"Risk score {risk_assessment.composite_score}/10.0 "
                        f"exceeds confirmation threshold "
                        f"({self._risk.require_confirmation_threshold}). "
                        f"{risk_assessment.explanation}"
                    )

        # ------------------------------------------------------------------
        # Audit (always, regardless of decision)
        # ------------------------------------------------------------------
        audit_id = self._audit.record(
            request_id=request.request_id,
            agent_id=request.agent_id,
            action_type=action_type,
            action_target=request.action.target,
            action_parameters=request.action.parameters,
            decision=decision.value,
            reason=reason,
            policy_evaluations=policy_evaluations,
            session_id=request.context.session_id,
        )

        # ------------------------------------------------------------------
        # Telemetry collection
        # ------------------------------------------------------------------
        latency_ms = (time.perf_counter() - start_time) * 1000
        self._record_decision_metrics(decision, latency_ms)

        return AGPResponse(
            request_id=request.request_id,
            decision=decision,
            reason=reason,
            audit_id=audit_id,
            risk_score=risk_assessment.composite_score,
            risk_category=risk_assessment.risk_category.value,
            risk_breakdown=risk_assessment.score_breakdown,
        )

    # ------------------------------------------------------------------
    # Metrics and telemetry
    # ------------------------------------------------------------------

    def _record_decision_metrics(self, decision: Decision, latency_ms: float) -> None:
        """Record metrics for a decision (H-2: thread-safe)."""
        with self._metrics_lock:
            self._metrics.total_decisions += 1
            self._metrics.total_latency_ms += latency_ms
            self._metrics.avg_latency_ms = (
                self._metrics.total_latency_ms / self._metrics.total_decisions
            )

            if decision == Decision.APPROVED:
                self._metrics.approved_count += 1
            elif decision == Decision.DENIED:
                self._metrics.denied_count += 1
            elif decision == Decision.ESCALATE:
                self._metrics.deferred_count += 1

    def get_metrics(self) -> DecisionMetrics:
        """Get current decision metrics (thread-safe snapshot)."""
        with self._metrics_lock:
            return DecisionMetrics(
                total_decisions=self._metrics.total_decisions,
                approved_count=self._metrics.approved_count,
                denied_count=self._metrics.denied_count,
                deferred_count=self._metrics.deferred_count,
                capability_denials=self._metrics.capability_denials,
                policy_denials=self._metrics.policy_denials,
                total_latency_ms=self._metrics.total_latency_ms,
                avg_latency_ms=self._metrics.avg_latency_ms,
            )

    def reset_metrics(self) -> None:
        """Reset metrics counters to zero (thread-safe)."""
        with self._metrics_lock:
            self._metrics = DecisionMetrics()
