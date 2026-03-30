"""Risk Scoring Engine.

Computes composite risk scores for proposed AI agent actions as the
third stage of AEGIS's governance pipeline (after capability check
and policy evaluation).

Risk scoring considers five dimensions:

1. **Capability sensitivity** - inherent risk tier of the capability
   (low / medium / high / critical)
2. **Action severity** - destructiveness of the action type
   (SHELL_EXEC > FILE_WRITE > API_CALL > FILE_READ > TOOL_CALL > DATA_ACCESS)
3. **Target sensitivity** - sensitivity of the target resource
   based on pattern matching against known sensitive paths
4. **Historical attempt rate** - frequency of recent requests from
   this agent (computed from audit trail)
5. **Behavioral anomaly** - deviation from the agent's historical
   baseline (repeated targets, unusual action types)

Federation signals (dimension 6) are deferred to the federation
layer (GFN-1).

Score range: 0.0-10.0, aligned with AGP-1 DECISION_RESPONSE spec.
Risk categories: data_access, system_control, capability_elevation,
behavioral_anomaly.

Integration with the Decision Engine:
- If policy decision is APPROVED but risk_score >= escalation threshold,
  the decision is overridden to REQUIRE_CONFIRMATION or ESCALATE.
- This implements the proportionality gate required by RT-014 / T3001.
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .audit import AuditSystem

logger = logging.getLogger("aegis_core.risk")

# ===================================================================
# Risk categories (AGP-1 spec)
# ===================================================================


class RiskCategory(StrEnum):
    """Risk category for classification in AGP-1 responses."""

    DATA_ACCESS = "data_access"
    SYSTEM_CONTROL = "system_control"
    CAPABILITY_ELEVATION = "capability_elevation"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"


# ===================================================================
# Risk tiers (RFC-0003: low, medium, high, critical)
# ===================================================================

CAPABILITY_RISK_WEIGHTS: MappingProxyType[str, float] = MappingProxyType({
    "low": 1.0,
    "medium": 3.0,
    "high": 6.0,
    "critical": 9.0,
})

# ===================================================================
# Action severity (inherent destructiveness by ActionType)
# ===================================================================

ACTION_SEVERITY: MappingProxyType[str, float] = MappingProxyType({
    "shell_exec": 9.0,
    "file_write": 6.0,
    "api_call": 5.0,
    "data_access": 4.0,
    "file_read": 2.0,
    "tool_call": 3.0,
})

# ===================================================================
# Target sensitivity patterns
# ===================================================================

_SENSITIVE_TARGET_PATTERNS: list[tuple[str, float, str]] = [
    # (glob pattern, risk score contribution, reason)
    # System-critical paths
    ("/etc/*", 8.0, "system configuration"),
    ("/root/*", 9.0, "root home directory"),
    ("C:/Windows/*", 8.0, "Windows system directory"),
    # Production infrastructure
    ("*production*", 5.0, "production environment"),
    ("*prod*", 4.0, "production environment"),
    # Database operations
    ("*DROP*", 9.0, "destructive SQL"),
    ("*DELETE*", 7.0, "destructive SQL"),
    ("*TRUNCATE*", 8.0, "destructive SQL"),
    # Destructive shell commands
    ("rm *", 7.0, "file removal"),
    ("rm -rf *", 9.5, "recursive forced removal"),
    ("format *", 9.0, "disk format"),
    ("mkfs*", 9.0, "filesystem creation"),
    ("dd if=*", 8.0, "disk-level I/O"),
    ("shred *", 9.0, "secure file/disk destruction"),
    ("find * -delete", 8.0, "recursive find-and-delete"),
    ("wipefs*", 9.0, "filesystem signature wipe"),
    # Credential/secret paths
    ("*.pem", 7.0, "certificate/key file"),
    ("*.key", 7.0, "private key"),
    ("*id_rsa*", 8.0, "SSH private key"),
    ("*passwd*", 7.0, "password file"),
    ("*shadow*", 9.0, "shadow password file"),
    ("*.env", 6.0, "environment secrets"),
    # Network exfiltration
    ("*evil*", 6.0, "suspicious target name"),
    ("*exfiltrat*", 8.0, "exfiltration indicator"),
]


# ===================================================================
# Risk assessment result
# ===================================================================

@dataclass
class RiskAssessment:
    """The result of a risk scoring evaluation.

    Attributes
    ----------
    composite_score : float
        Overall risk score (0.0-10.0). Higher = riskier.
    capability_risk : float
        Risk contribution from capability tier.
    action_severity : float
        Risk contribution from action type.
    target_sensitivity : float
        Risk contribution from target pattern matching.
    historical_rate : float
        Risk contribution from request frequency.
    behavioral_anomaly : float
        Risk contribution from behavioral deviation.
    risk_category : RiskCategory
        Classified risk category for AGP-1 response.
    explanation : str
        Human-readable explanation of the risk assessment.
    score_breakdown : dict[str, float]
        Per-dimension score breakdown for AGP-1 policy_trace.
    """

    composite_score: float
    capability_risk: float = 0.0
    action_severity: float = 0.0
    target_sensitivity: float = 0.0
    historical_rate: float = 0.0
    behavioral_anomaly: float = 0.0
    risk_category: RiskCategory = RiskCategory.DATA_ACCESS
    explanation: str = ""
    score_breakdown: dict[str, float] = field(default_factory=dict)


# ===================================================================
# Thresholds
# ===================================================================

# Default thresholds for risk-based decision override
DEFAULT_REQUIRE_CONFIRMATION_THRESHOLD = 7.0
DEFAULT_ESCALATION_THRESHOLD = 9.0


# ===================================================================
# Risk engine
# ===================================================================

class RiskEngine:
    """Computes composite risk scores for proposed actions.

    The risk engine evaluates five dimensions and produces a normalized
    0.0-10.0 composite score.  When integrated with the Decision Engine,
    scores above configurable thresholds override APPROVED decisions to
    REQUIRE_CONFIRMATION or ESCALATE (proportionality gate, RT-014 / T3001).

    Parameters
    ----------
    audit_system : AuditSystem, optional
        Audit system for computing historical and behavioral risk.
        If None, historical and behavioral dimensions score 0.0.
    require_confirmation_threshold : float
        Composite score at or above which APPROVED is overridden to
        REQUIRE_CONFIRMATION. Default: 7.0.
    escalation_threshold : float
        Composite score at or above which APPROVED is overridden to
        ESCALATE. Default: 9.0.
    """

    def __init__(
        self,
        audit_system: AuditSystem | None = None,
        require_confirmation_threshold: float = DEFAULT_REQUIRE_CONFIRMATION_THRESHOLD,
        escalation_threshold: float = DEFAULT_ESCALATION_THRESHOLD,
    ) -> None:
        self._audit = audit_system
        self.require_confirmation_threshold = require_confirmation_threshold
        self.escalation_threshold = escalation_threshold

    # ------------------------------------------------------------------
    # Main scoring method
    # ------------------------------------------------------------------

    def assess(
        self,
        *,
        action_type: str,
        target: str,
        agent_id: str,
        capability_tier: str = "medium",
        parameters: dict[str, Any] | None = None,
    ) -> RiskAssessment:
        """Compute a comprehensive risk assessment for a proposed action.

        Parameters
        ----------
        action_type : str
            The action type value (e.g., "shell_exec", "file_read").
        target : str
            The target resource string.
        agent_id : str
            The requesting agent's identifier.
        capability_tier : str
            The risk tier of the capability ("low", "medium", "high",
            "critical"). Default: "medium".
        parameters : dict, optional
            Action parameters (used for additional context).

        Returns
        -------
        RiskAssessment
            Complete risk assessment with composite score, per-dimension
            breakdown, category, and explanation.

        Raises
        ------
        TypeError
            If action_type, target, or agent_id are not strings.
        """
        # Input validation — reject None and non-string inputs
        if not isinstance(action_type, str):
            raise TypeError(f"action_type must be str, got {type(action_type).__name__}")
        if not isinstance(target, str):
            raise TypeError(f"target must be str, got {type(target).__name__}")
        if not isinstance(agent_id, str):
            raise TypeError(f"agent_id must be str, got {type(agent_id).__name__}")

        # Warn on unrecognized capability tier or action type
        if capability_tier not in CAPABILITY_RISK_WEIGHTS:
            logger.warning(
                "Unrecognized capability_tier %r — defaulting to 5.0",
                capability_tier,
            )
        if action_type and action_type not in ACTION_SEVERITY:
            logger.warning(
                "Unrecognized action_type %r — defaulting to 5.0",
                action_type,
            )

        cap_risk = self._score_capability(capability_tier)
        act_severity = self._score_action_severity(action_type)
        tgt_sensitivity = self._score_target_sensitivity(target)
        hist_rate = self._score_historical_rate(agent_id)
        behav_anomaly = self._score_behavioral_anomaly(
            agent_id, action_type, target
        )

        # Weighted composite: action severity and target sensitivity
        # are the strongest signals for proportionality.
        # Base weights sum to 1.0.
        composite = (
            0.10 * cap_risk
            + 0.30 * act_severity
            + 0.30 * tgt_sensitivity
            + 0.10 * hist_rate
            + 0.10 * behav_anomaly
        )

        # Amplifier: when both action severity AND target sensitivity
        # are high (>= 7.0 each), the combined danger is multiplicative,
        # not merely additive. Apply a boost to ensure destructive
        # actions against sensitive targets reliably cross thresholds.
        if act_severity >= 7.0 and tgt_sensitivity >= 7.0:
            amplifier = min(act_severity, tgt_sensitivity) / 10.0
            composite += amplifier * 3.0

        # Clamp to 0.0-10.0
        composite = max(0.0, min(10.0, composite))

        category = self._classify_category(action_type, target)
        explanation = self._build_explanation(
            composite, cap_risk, act_severity, tgt_sensitivity,
            hist_rate, behav_anomaly, capability_tier, action_type, target,
        )

        return RiskAssessment(
            composite_score=round(composite, 2),
            capability_risk=round(cap_risk, 2),
            action_severity=round(act_severity, 2),
            target_sensitivity=round(tgt_sensitivity, 2),
            historical_rate=round(hist_rate, 2),
            behavioral_anomaly=round(behav_anomaly, 2),
            risk_category=category,
            explanation=explanation,
            score_breakdown={
                "capability_sensitivity": round(cap_risk, 2),
                "action_severity": round(act_severity, 2),
                "target_sensitivity": round(tgt_sensitivity, 2),
                "historical_attempt_rate": round(hist_rate, 2),
                "behavioral_anomaly": round(behav_anomaly, 2),
            },
        )

    # ------------------------------------------------------------------
    # Dimension 1: Capability sensitivity
    # ------------------------------------------------------------------

    def _score_capability(self, capability_tier: str) -> float:
        """Score based on the capability's declared risk tier."""
        return CAPABILITY_RISK_WEIGHTS.get(capability_tier, 5.0)

    # ------------------------------------------------------------------
    # Dimension 2: Action severity
    # ------------------------------------------------------------------

    def _score_action_severity(self, action_type: str) -> float:
        """Score based on the inherent destructiveness of the action type."""
        return ACTION_SEVERITY.get(action_type, 5.0)

    # ------------------------------------------------------------------
    # Dimension 3: Target sensitivity
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_unicode(s: str) -> str:
        """Normalize Unicode homoglyphs that could evade pattern matching.

        Handles the same homoglyphs as the RFC-0006 evaluator to maintain
        consistency across the governance pipeline (T10004).
        """
        # Strip null bytes
        s = s.replace("\x00", "")
        # U+FF0E (FULLWIDTH FULL STOP) → .
        s = s.replace("\uFF0E", ".")
        # U+2215 (DIVISION SLASH), U+2044 (FRACTION SLASH), U+FF0F (FULLWIDTH SOLIDUS) → /
        for ch in ("\u2215", "\u2044", "\uFF0F"):
            s = s.replace(ch, "/")
        # U+FF3C (FULLWIDTH REVERSE SOLIDUS) → \
        s = s.replace("\uFF3C", "\\")
        # Collapse consecutive dots from homoglyph replacement
        import re
        s = re.sub(r"\.{2,}", ".", s)
        return s

    def _score_target_sensitivity(self, target: str) -> float:
        """Score based on pattern matching against known sensitive targets.

        Normalizes the target path before matching to prevent evasion
        via redundant segments, double slashes, case variation, or
        Unicode homoglyphs (RT-RISK-002, T10004).
        """
        import posixpath

        # Normalize Unicode homoglyphs first (T10004)
        unicode_normalized = self._normalize_unicode(target)

        # Normalize path-like targets to prevent obfuscation evasion
        normalized = (
            unicode_normalized
            if "://" in unicode_normalized
            else posixpath.normpath(unicode_normalized)
        )

        # Check all three variants: original, Unicode-normalized, path-normalized
        variants = {target, unicode_normalized, normalized}

        max_score = 0.0
        for pattern, score, _reason in _SENSITIVE_TARGET_PATTERNS:
            for variant in variants:
                if (
                    fnmatch.fnmatch(variant, pattern)
                    or fnmatch.fnmatch(variant.lower(), pattern.lower())
                ):
                    max_score = max(max_score, score)
                    break  # no need to check other variants for this pattern
        return max_score

    # ------------------------------------------------------------------
    # Dimension 4: Historical attempt rate
    # ------------------------------------------------------------------

    def _score_historical_rate(self, agent_id: str) -> float:
        """Score based on the agent's recent request frequency.

        Higher frequency → higher risk. An agent making an unusual
        number of requests may be in a runaway loop or coordinated
        attack.
        """
        if self._audit is None:
            return 0.0

        recent = self._audit.get_agent_history(agent_id, limit=100)
        count = len(recent)

        # Thresholds: 0-10 requests = low, 10-50 = moderate, 50+ = high
        if count < 10:
            return 0.0
        if count < 30:
            return 3.0
        if count < 50:
            return 5.0
        if count < 80:
            return 7.0
        return 9.0

    # ------------------------------------------------------------------
    # Dimension 5: Behavioral anomaly
    # ------------------------------------------------------------------

    def _score_behavioral_anomaly(
        self, agent_id: str, action_type: str, target: str
    ) -> float:
        """Score based on deviation from the agent's historical baseline.

        Detects:
        - Action type the agent has never used before
        - Repeated identical targets (possible loop or fixation)
        - High denial rate (agent probing boundaries)
        """
        if self._audit is None:
            return 0.0

        recent = self._audit.get_agent_history(agent_id, limit=50)
        if not recent:
            return 0.0

        anomaly_score = 0.0

        # Check if action_type is new for this agent
        historical_types = {r.action_type for r in recent}
        if action_type not in historical_types and len(historical_types) > 0:
            anomaly_score += 3.0

        # Check for repeated identical targets (fixation)
        target_counts: dict[str, int] = {}
        for record in recent:
            target_counts[record.action_target] = (
                target_counts.get(record.action_target, 0) + 1
            )
        if target in target_counts and target_counts[target] >= 5:
            anomaly_score += 4.0

        # Check denial rate (boundary probing)
        denied = sum(1 for r in recent if r.decision == "denied")
        if len(recent) > 5:
            denial_rate = denied / len(recent)
            if denial_rate > 0.5:
                anomaly_score += 3.0

        return min(10.0, anomaly_score)

    # ------------------------------------------------------------------
    # Category classification
    # ------------------------------------------------------------------

    def _classify_category(
        self, action_type: str, target: str
    ) -> RiskCategory:
        """Classify the risk into an AGP-1 risk category."""
        if action_type in ("shell_exec", "file_write"):
            return RiskCategory.SYSTEM_CONTROL
        if action_type in ("file_read", "data_access"):
            return RiskCategory.DATA_ACCESS
        target_lower = target.lower()
        if "admin" in target_lower or "grant" in target_lower:
            return RiskCategory.CAPABILITY_ELEVATION
        return RiskCategory.DATA_ACCESS

    # ------------------------------------------------------------------
    # Explanation
    # ------------------------------------------------------------------

    def _build_explanation(
        self,
        composite: float,
        cap_risk: float,
        act_severity: float,
        tgt_sensitivity: float,
        hist_rate: float,
        behav_anomaly: float,
        capability_tier: str,
        action_type: str,
        target: str,
    ) -> str:
        """Build a human-readable risk explanation."""
        parts = [
            f"Risk score {composite:.1f}/10.0 for {action_type} on '{target}'.",
        ]

        factors = []
        if act_severity >= 7.0:
            factors.append(
                f"high action severity ({action_type}={act_severity:.0f})"
            )
        if tgt_sensitivity >= 5.0:
            factors.append(
                f"sensitive target ({tgt_sensitivity:.0f})"
            )
        if cap_risk >= 6.0:
            factors.append(
                f"high capability tier ({capability_tier}={cap_risk:.0f})"
            )
        if hist_rate >= 5.0:
            factors.append(f"elevated request rate ({hist_rate:.0f})")
        if behav_anomaly >= 3.0:
            factors.append(f"behavioral anomaly ({behav_anomaly:.0f})")

        if factors:
            parts.append("Factors: " + "; ".join(factors) + ".")
        else:
            parts.append("No significant risk factors.")

        return " ".join(parts)
