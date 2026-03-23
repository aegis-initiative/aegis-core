"""
aegis_core.capability — Capability Registry

The capability registry manages the declaration and verification of AI system
capabilities within the AEGIS governance framework. In the AGP-1 protocol,
every governed system must declare its capabilities before requesting action
approval.

Capabilities represent what a system *can* do (e.g., "network_access",
"file_write", "content_generation"). Permission grants determine what a
system is *allowed* to do within a given governance context.

Key concepts:
    - Capability Declaration: A system registers its full set of capabilities
      at enrollment time.
    - Permission Grant: An administrator or policy grants a system permission
      to exercise specific capabilities under specific conditions.
    - Capability Check: During ACTION_PROPOSE evaluation, the gateway verifies
      that the proposed action falls within the system's granted capabilities.

This module uses only the Python standard library.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class Capability:
    """A single capability that an AI system can declare."""
    name: str
    description: str = ""
    risk_tier: str = "standard"  # "low", "standard", "elevated", "critical"


@dataclass
class PermissionGrant:
    """A grant allowing a system to exercise a specific capability."""
    capability_name: str
    conditions: list[str] = field(default_factory=list)
    expires_at: str | None = None  # ISO 8601 timestamp, or None for no expiry


class CapabilityRegistry:
    """
    Manages capability declarations and permission grants for governed systems.

    Each system is identified by a unique system_id. Systems must declare
    capabilities before they can be granted permissions, and permissions
    must be granted before actions requiring those capabilities are approved.
    """

    def __init__(self) -> None:
        self._declarations: dict[str, list[Capability]] = {}
        self._grants: dict[str, list[PermissionGrant]] = {}

    def declare(self, system_id: str, capabilities: list[Capability]) -> None:
        """Register capabilities for a governed system."""
        self._declarations[system_id] = list(capabilities)
        logger.info("System %s declared %d capabilities", system_id, len(capabilities))

    def grant(self, system_id: str, grant: PermissionGrant) -> None:
        """Grant a system permission to exercise a capability."""
        if system_id not in self._declarations:
            raise ValueError(f"System {system_id} has not declared capabilities")
        self._grants.setdefault(system_id, []).append(grant)
        logger.info("Granted %s to system %s", grant.capability_name, system_id)

    def check(self, system_id: str, capability_name: str) -> bool:
        """
        Check whether a system has been granted a specific capability.

        Returns True if the system has an active grant for the capability.
        """
        grants = self._grants.get(system_id, [])
        return any(g.capability_name == capability_name for g in grants)
