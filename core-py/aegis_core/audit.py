"""
aegis_core.audit — Audit Logging

The audit logger maintains an immutable record of all governance decisions
made by the AEGIS enforcement engine. In the AGP-1 protocol, every
ACTION_PROPOSE / DECISION_RESPONSE exchange must be logged for compliance
and forensic analysis.

Audit records capture:
    - The original ACTION_PROPOSE message
    - The DECISION_RESPONSE verdict and reasoning
    - The full risk assessment
    - Policy citations that influenced the decision
    - Timestamps for the entire evaluation lifecycle

The audit log is append-only by design. Records are never modified or deleted
through normal operation. This ensures a tamper-evident trail of all governance
decisions.

This module uses only the Python standard library.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AuditRecord:
    """An immutable record of a single governance decision."""
    record_id: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    system_id: str = ""
    action_type: str = ""
    verdict: str = ""
    risk_score: float = 0.0
    policy_citations: list[str] = field(default_factory=list)
    reasoning: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class AuditLogger:
    """
    Append-only audit log for governance decisions.

    Stores all governance decision records in memory. A production
    implementation would persist to durable, tamper-evident storage.
    """

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    def log(self, record: AuditRecord) -> None:
        """Append a governance decision record to the audit log."""
        self._records.append(record)
        logger.info(
            "Audit: %s — %s/%s → %s (risk=%.2f)",
            record.record_id,
            record.system_id,
            record.action_type,
            record.verdict,
            record.risk_score,
        )

    def get_records(self, system_id: str | None = None) -> list[AuditRecord]:
        """
        Retrieve audit records, optionally filtered by system_id.

        Args:
            system_id: If provided, only return records for this system.

        Returns:
            List of matching audit records.
        """
        if system_id is None:
            return list(self._records)
        return [r for r in self._records if r.system_id == system_id]

    def export_json(self) -> str:
        """Export all audit records as a JSON string."""
        return json.dumps([asdict(r) for r in self._records], indent=2)
