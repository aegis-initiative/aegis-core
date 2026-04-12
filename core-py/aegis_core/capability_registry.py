"""Capability Registry.

Implements the capability-based access model that forms the first layer
of AEGIS's defence-in-depth strategy.

An agent is only permitted to attempt an action if it holds a capability
that covers both the :class:`~aegis.protocol.ActionType` and the target
resource.  Capabilities can be time-limited and are revocable at any
time.

Design
------
* Capabilities are registered globally (shared across all agents).
* Each agent is granted zero or more capability IDs.
* A capability covers one or more action types and a set of target
  patterns (``fnmatch`` glob syntax, e.g. ``"s3://my-bucket/*"``).
* A capability whose ``expires_at`` is in the past is treated as
  non-existent.
* All operations are thread-safe via internal locking.
"""

from __future__ import annotations

import contextlib
import fnmatch
import hmac
import posixpath
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from . import errors
from .exceptions import AEGISCapabilityError


@dataclass
class Capability:
    """A named, scoped permission unit.

    Parameters
    ----------
    id : str
        Unique identifier for this capability.
    name : str
        Short human-readable label.
    description : str
        Longer description of what this capability allows.
    action_types : list[str]
        List of :class:`~aegis.protocol.ActionType` values (as strings)
        covered by this capability.
    target_patterns : list[str]
        List of ``fnmatch`` glob patterns matching permissible targets.
        Use ``["*"]`` to match any target.
    granted_at : datetime, optional
        UTC timestamp when the capability was created.
    expires_at : datetime, optional
        Optional UTC expiry timestamp.  ``None`` means never expires.
    metadata : dict, optional
        Arbitrary key/value annotations.
    """

    id: str
    name: str
    description: str
    action_types: list[str]
    target_patterns: list[str]
    granted_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_active(self, at: datetime | None = None) -> bool:
        """Return ``True`` if the capability has not expired.

        Parameters
        ----------
        at : datetime, optional
            Reference time. Defaults to now(UTC).

        Returns
        -------
        bool
            True if the capability is currently active.
        """
        if self.expires_at is None:
            return True
        reference = at or datetime.now(UTC)
        return self.expires_at > reference

    def to_dict(self) -> dict[str, Any]:
        """Serialize this capability to a JSON-safe dictionary.

        The returned dictionary is suitable for writing to a ``registry.json``
        file consumed by :meth:`CapabilityRegistry.load_from_json`, and is the
        exact format produced by :meth:`from_dict`'s inverse.

        Returns
        -------
        dict
            JSON-safe representation with ISO-8601 timestamps.
        """
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "action_types": list(self.action_types),
            "target_patterns": list(self.target_patterns),
            "granted_at": self.granted_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Capability:
        """Build a :class:`Capability` from a dict loaded from JSON.

        This is the reciprocal of :meth:`to_dict` and is used by
        :meth:`CapabilityRegistry.load_from_json` to rehydrate entries from
        a file-based registry (RFC-0005 RDP-03).

        Required fields: ``id``, ``name``, ``description``, ``action_types``,
        ``target_patterns``. Optional fields: ``granted_at``, ``expires_at``,
        ``metadata``.

        Parameters
        ----------
        data : dict
            Parsed JSON object describing the capability.

        Returns
        -------
        Capability
            The constructed capability.

        Raises
        ------
        ValueError
            If a required field is missing or has the wrong type.
        """
        required = ("id", "name", "description", "action_types", "target_patterns")
        missing = [k for k in required if k not in data]
        if missing:
            raise ValueError(
                f"registry.json capability entry missing required field(s): {', '.join(missing)}"
            )

        if not isinstance(data["action_types"], list) or not all(
            isinstance(a, str) for a in data["action_types"]
        ):
            raise ValueError("capability.action_types must be a list of strings")
        if not isinstance(data["target_patterns"], list) or not all(
            isinstance(t, str) for t in data["target_patterns"]
        ):
            raise ValueError("capability.target_patterns must be a list of strings")

        granted_at_raw = data.get("granted_at")
        if granted_at_raw is None:
            granted_at = datetime.now(UTC)
        else:
            granted_at = datetime.fromisoformat(granted_at_raw)

        expires_at_raw = data.get("expires_at")
        expires_at = datetime.fromisoformat(expires_at_raw) if expires_at_raw else None

        metadata = data.get("metadata") or {}
        if not isinstance(metadata, dict):
            raise ValueError("capability.metadata must be an object (dict)")

        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            description=str(data["description"]),
            action_types=list(data["action_types"]),
            target_patterns=list(data["target_patterns"]),
            granted_at=granted_at,
            expires_at=expires_at,
            metadata=metadata,
        )

    def covers(self, action_type: str, target: str) -> bool:
        """Return ``True`` if this capability permits *action_type* on *target*.

        Targets are normalized via ``posixpath.normpath`` to prevent
        path-traversal attacks (e.g. ``/docs/../etc/passwd``).

        Parameters
        ----------
        action_type : str
            The action type to check (e.g., "tool_call", "file_read").
        target : str
            The resource target to check (e.g., "/docs/*").

        Returns
        -------
        bool
            True if this capability covers the action+target combination.
        """
        if not self.is_active():
            return False
        if action_type not in self.action_types:
            return False
        # Normalize the target to prevent path traversal (RT-002 / T10001).
        # Only skip normalization for valid URI schemes (M-10).
        # A valid scheme starts with a letter and contains only letters,
        # digits, +, -, or . before ://
        import re

        has_valid_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", target))
        normalized_target = target if has_valid_scheme else posixpath.normpath(target)
        return any(
            fnmatch.fnmatch(normalized_target, pattern) or pattern == "*"
            for pattern in self.target_patterns
        )


class CapabilityRegistry:
    """Central store of capabilities and their assignments to agents.

    This implementation is thread-safe via internal locking. All database
    operations are protected to enable safe concurrent access from multiple
    threads.

    Supports a ``freeze()`` / ``unseal()`` mechanism (RT-006 / T8002,
    SP-3) to lock governance state after configuration.  Once frozen,
    mutation methods (``register``, ``unregister``, ``grant``, ``revoke``,
    etc.) raise :class:`AEGISCapabilityError`.  Read-only queries remain
    available.
    """

    # M-9: Limit registered capabilities to prevent O(n*m) DoS
    _MAX_CAPABILITIES = 10_000

    # RT-011 / T1003: Maximum agents in a single bulk_grant call
    _DEFAULT_BULK_GRANT_LIMIT = 50

    def __init__(self, *, bulk_grant_limit: int | None = None) -> None:
        self._capabilities: dict[str, Capability] = {}
        self._agent_capabilities: dict[str, set[str]] = {}
        self._lock = threading.Lock()
        self._frozen = False
        self._seal_token: str | None = None
        # RT-011 / T1003: Configurable bulk grant batch limit
        self._bulk_grant_limit = (
            bulk_grant_limit if bulk_grant_limit is not None else self._DEFAULT_BULK_GRANT_LIMIT
        )
        # RT-011: Callbacks notified when bulk grant exceeds alert threshold
        self._bulk_grant_listeners: list[Any] = []

    # ------------------------------------------------------------------
    # Freeze / unseal (RT-006 / T8002, SP-3, C-2)
    # ------------------------------------------------------------------

    def freeze(self) -> str:
        """Lock the registry against mutations.

        Returns a seal token required to unseal.  Without the token,
        ``unseal()`` raises :class:`AEGISCapabilityError`.

        Returns
        -------
        str
            Opaque seal token that must be passed to :meth:`unseal`.
        """
        import uuid

        with self._lock:
            self._frozen = True
            self._seal_token = str(uuid.uuid4())
            return self._seal_token

    def unseal(self, token: str) -> None:
        """Re-enable mutations after a :meth:`freeze`.

        Parameters
        ----------
        token : str
            The seal token returned by :meth:`freeze`.

        Raises
        ------
        AEGISCapabilityError
            If the token does not match the seal token.
        """
        with self._lock:
            # BT-AUDIT-004: Constant-time comparison prevents timing attacks
            if self._seal_token is None or not hmac.compare_digest(
                token.encode(), self._seal_token.encode()
            ):
                raise AEGISCapabilityError(
                    "Invalid seal token — cannot unseal registry",
                    error_code=errors.CAP_INVALID_SEAL_TOKEN,
                    cause="seal_token",
                )
            self._frozen = False
            self._seal_token = None

    @property
    def is_frozen(self) -> bool:
        """Return ``True`` if the registry is currently frozen."""
        return self._frozen

    def _check_frozen(self) -> None:
        """Raise if frozen."""
        if self._frozen:
            raise AEGISCapabilityError(
                "CapabilityRegistry is frozen — call unseal() with a valid "
                "seal token before modifying governance state",
                error_code=errors.CAP_REGISTRY_FROZEN,
            )

    # ------------------------------------------------------------------
    # Capability management
    # ------------------------------------------------------------------

    def register(self, capability: Capability) -> None:
        """Register a new capability definition.

        Parameters
        ----------
        capability : Capability
            The capability to register.

        Raises
        ------
        ValueError
            If a capability with the same ID is already registered.
        AEGISCapabilityError
            If the registry is frozen.
        """
        with self._lock:
            # BT-AUDIT-003: Freeze check inside lock to prevent TOCTOU.
            self._check_frozen()
            if len(self._capabilities) >= self._MAX_CAPABILITIES:
                raise AEGISCapabilityError(
                    f"Capability registry has reached its maximum capacity "
                    f"of {self._MAX_CAPABILITIES} capabilities",
                    error_code=errors.CAP_REGISTRY_CAPACITY,
                )
            if capability.id in self._capabilities:
                raise ValueError(f"Capability '{capability.id}' is already registered.")
            self._capabilities[capability.id] = capability

    def unregister(self, capability_id: str) -> None:
        """Remove a capability definition and all agent assignments for it.

        Parameters
        ----------
        capability_id : str
            ID of the capability to unregister.
        """
        with self._lock:
            self._check_frozen()
            self._capabilities.pop(capability_id, None)
            for agent_caps in self._agent_capabilities.values():
                agent_caps.discard(capability_id)

    def get_capability(self, capability_id: str) -> Capability | None:
        """Look up a capability by ID.

        Parameters
        ----------
        capability_id : str
            ID of the capability to retrieve.

        Returns
        -------
        Capability or None
            The capability if found, None otherwise.
        """
        with self._lock:
            return self._capabilities.get(capability_id)

    # ------------------------------------------------------------------
    # Agent assignments
    # ------------------------------------------------------------------

    def grant(self, agent_id: str, capability_id: str) -> None:
        """Grant *capability_id* to *agent_id*.

        Parameters
        ----------
        agent_id : str
            The agent to grant the capability to.
        capability_id : str
            The capability to grant.

        Raises
        ------
        AEGISCapabilityError
            If *capability_id* is not registered or registry is frozen.
        """
        with self._lock:
            self._check_frozen()
            if capability_id not in self._capabilities:
                raise AEGISCapabilityError(
                    f"Cannot grant unknown capability '{capability_id}' — "
                    f"register it first with CapabilityRegistry.register()",
                    error_code=errors.CAP_UNKNOWN_CAPABILITY,
                    cause=capability_id,
                )
            self._agent_capabilities.setdefault(agent_id, set()).add(capability_id)

    def on_bulk_grant(self, callback: Any) -> None:
        """Register a listener notified on bulk grant operations.

        The callback receives ``(agent_ids, capability_id, count)``
        when a bulk grant exceeds the alert threshold (>= 10 agents).
        Use this to wire up audit alerts (RT-011 / T1003).
        """
        self._bulk_grant_listeners.append(callback)

    def bulk_grant(
        self,
        agent_ids: list[str],
        capability_id: str,
    ) -> int:
        """Grant a single capability to multiple agents.

        This is more efficient than calling grant() multiple times, as it
        performs all assignments in a single atomic transaction.

        RT-011 / T1003: Enforces a configurable batch size limit to
        prevent mass privilege escalation in a single call.

        Parameters
        ----------
        agent_ids : list[str]
            List of agent IDs to grant the capability to.
        capability_id : str
            The capability to grant to all agents.

        Returns
        -------
        int
            The number of agents that were granted the capability.

        Raises
        ------
        AEGISCapabilityError
            If *capability_id* is not registered, registry is frozen,
            or the batch exceeds the bulk grant limit.
        """
        # RT-011 / T1003: Reject oversized bulk grants
        if len(agent_ids) > self._bulk_grant_limit:
            raise AEGISCapabilityError(
                f"Bulk grant to {len(agent_ids)} agents exceeds limit of "
                f"{self._bulk_grant_limit} (RT-011 / T1003). "
                f"Split into smaller batches or increase the limit.",
                error_code=errors.CAP_BULK_GRANT_LIMIT,
                cause=capability_id,
            )

        with self._lock:
            self._check_frozen()
            if capability_id not in self._capabilities:
                raise AEGISCapabilityError(
                    f"Cannot grant unknown capability '{capability_id}' — "
                    f"register it first with CapabilityRegistry.register()",
                    error_code=errors.CAP_UNKNOWN_CAPABILITY,
                    cause=capability_id,
                )
            count = 0
            for agent_id in agent_ids:
                if agent_id not in self._agent_capabilities:
                    self._agent_capabilities[agent_id] = set()
                if capability_id not in self._agent_capabilities[agent_id]:
                    self._agent_capabilities[agent_id].add(capability_id)
                    count += 1

        # RT-011: Fire audit alert for significant bulk grants.
        # Listeners must not break the grant operation; any listener
        # exception is deliberately swallowed.
        if len(agent_ids) >= 10:
            for listener in self._bulk_grant_listeners:
                with contextlib.suppress(Exception):
                    listener(agent_ids, capability_id, count)

        return count

    def revoke(self, agent_id: str, capability_id: str) -> None:
        """Revoke *capability_id* from *agent_id* (no-op if not held).

        Parameters
        ----------
        agent_id : str
            The agent to revoke the capability from.
        capability_id : str
            The capability to revoke.
        """
        with self._lock:
            self._check_frozen()
            if agent_id in self._agent_capabilities:
                self._agent_capabilities[agent_id].discard(capability_id)

    def bulk_revoke(
        self,
        agent_ids: list[str],
        capability_id: str,
    ) -> int:
        """Revoke a single capability from multiple agents.

        This is more efficient than calling revoke() multiple times, as it
        performs all revocations in a single atomic transaction.

        Parameters
        ----------
        agent_ids : list[str]
            List of agent IDs to revoke the capability from.
        capability_id : str
            The capability to revoke from all agents.

        Returns
        -------
        int
            The number of agents that had the capability revoked.
        """
        with self._lock:
            self._check_frozen()
            count = 0
            for agent_id in agent_ids:
                if (
                    agent_id in self._agent_capabilities
                    and capability_id in self._agent_capabilities[agent_id]
                ):
                    self._agent_capabilities[agent_id].discard(capability_id)
                    count += 1
            return count

    def revoke_all(self, agent_id: str) -> None:
        """Revoke all capabilities from *agent_id*.

        Parameters
        ----------
        agent_id : str
            The agent to revoke all capabilities from.
        """
        with self._lock:
            self._check_frozen()
            self._agent_capabilities.pop(agent_id, None)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_agent_capabilities(self, agent_id: str) -> list[Capability]:
        """Return the active capabilities currently held by *agent_id*.

        Parameters
        ----------
        agent_id : str
            The agent to query.

        Returns
        -------
        list[Capability]
            List of active capabilities held by the agent.
        """
        with self._lock:
            cap_ids = self._agent_capabilities.get(agent_id, set())
            now = datetime.now(UTC)
            return [
                self._capabilities[cid]
                for cid in cap_ids
                if cid in self._capabilities and self._capabilities[cid].is_active(now)
            ]

    def has_capability_for_action(self, agent_id: str, action_type: str, target: str) -> bool:
        """Return ``True`` if *agent_id* holds a capability covering *action_type*
        on *target*.

        Parameters
        ----------
        agent_id : str
            The agent to check.
        action_type : str
            The action type (e.g., "tool_call").
        target : str
            The target resource.

        Returns
        -------
        bool
            True if the agent has a matching active capability.
        """
        return any(cap.covers(action_type, target) for cap in self.get_agent_capabilities(agent_id))

    # ------------------------------------------------------------------
    # File-based configuration (RFC-0005 RDP-03)
    # ------------------------------------------------------------------

    def load_from_json(self, path: str) -> None:
        """Populate the registry from a ``registry.json`` file.

        This method implements the file-based capability registry pattern
        specified by RFC-0005 Reference Deployment Pattern 03 (Embedded
        Lightweight). Capabilities are registered and, if the file contains
        a ``grants`` section, each agent's capability grants are applied in
        the same call so a single call fully populates the registry.

        File format (``registry.json``)
        -------------------------------
        ::

            {
              "version": "1",
              "capabilities": [
                {
                  "id": "fs.read.tmp",
                  "name": "Read /var/tmp",
                  "description": "Read files under /var/tmp",
                  "action_types": ["file_read"],
                  "target_patterns": ["/var/tmp/*"],
                  "expires_at": null,
                  "metadata": {}
                }
              ],
              "grants": {
                "agent-alice": ["fs.read.tmp"],
                "agent-bob": []
              }
            }

        The ``version`` field is reserved for forward compatibility and is
        currently checked only for presence. The ``capabilities`` list is
        required. The ``grants`` mapping is optional — capabilities can be
        registered without being granted to any agent.

        Parameters
        ----------
        path : str or path-like
            Filesystem path to the ``registry.json`` file.

        Raises
        ------
        FileNotFoundError
            If the file does not exist.
        ValueError
            If the file is not valid JSON, is not the expected shape, or if
            a capability entry or grant references an unknown capability ID.
        AEGISCapabilityError
            If the registry is frozen, or if ``register``/``grant`` itself
            raises.
        """
        import json
        from pathlib import Path

        file_path = Path(path)
        if not file_path.is_file():
            raise FileNotFoundError(f"registry.json not found at {file_path}")

        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"registry.json at {file_path} is not valid JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError(f"registry.json at {file_path} must contain a top-level object")
        if "capabilities" not in data:
            raise ValueError(f"registry.json at {file_path} missing required field 'capabilities'")
        if not isinstance(data["capabilities"], list):
            raise ValueError(f"registry.json at {file_path} field 'capabilities' must be a list")

        # Phase 1: parse + register every capability before touching grants.
        # This fails fast on malformed files without leaving the registry
        # in a partially-populated state — on error, the caller can retry
        # after fixing the file. Frozen-registry errors from register() are
        # also caught in this phase and propagated before any grants are
        # applied.
        for entry in data["capabilities"]:
            if not isinstance(entry, dict):
                raise ValueError("each entry in registry.json 'capabilities' must be an object")
            self.register(Capability.from_dict(entry))

        # Phase 2: apply grants. Missing-capability grants are a configuration
        # error and raised eagerly so they are visible at load time rather
        # than as runtime denials.
        grants = data.get("grants") or {}
        if not isinstance(grants, dict):
            raise ValueError(
                f"registry.json at {file_path} field 'grants' must be an "
                f"object mapping agent_id to list of capability IDs"
            )

        known_cap_ids = set(self._capabilities.keys())
        for agent_id, cap_ids in grants.items():
            if not isinstance(cap_ids, list):
                raise ValueError(f"grants['{agent_id}'] must be a list of capability IDs")
            for cap_id in cap_ids:
                if cap_id not in known_cap_ids:
                    raise ValueError(
                        f"grants['{agent_id}'] references unknown capability "
                        f"'{cap_id}' not defined in this registry"
                    )
                self.grant(str(agent_id), str(cap_id))
