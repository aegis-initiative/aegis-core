"""AEGISRuntime - convenience facade.

Wires all AEGIS components together into a single object that can be
used as the primary integration point for embedders.

Quick-start::

    from aegis_core import AEGISRuntime
    from aegis_core.capability_registry import Capability
    from aegis_core.policy_engine import Policy, PolicyEffect, PolicyCondition
    from aegis_core.protocol import ActionType

    runtime = AEGISRuntime()

    # 1. Register a capability
    runtime.capabilities.register(Capability(
        id="cap-read-docs",
        name="Read documentation files",
        description="Allows reading files under /docs",
        action_types=[ActionType.FILE_READ.value, ActionType.TOOL_CALL.value],
        target_patterns=["/docs/*", "read_*"],
    ))

    # 2. Grant the capability to an agent
    runtime.capabilities.grant("agent-1", "cap-read-docs")

    # 3. Add an allow policy
    runtime.policies.add_policy(Policy(
        id="pol-allow-docs",
        name="Allow documentation reads",
        description="Agents with the docs capability may read documentation.",
        effect=PolicyEffect.ALLOW,
        conditions=[],  # no extra conditions - capability check is sufficient
    ))

    # 4. Create a governed tool proxy for the agent
    proxy = runtime.create_tool_proxy("agent-1", "session-xyz")
    proxy.register_tool("read_doc", fn=lambda path: open(path).read(), target="read_doc")

    # 5. Invoke the tool - governance is applied transparently
    content = proxy.call("read_doc", path="/docs/intro.md")

Context manager usage::

    # Automatically manages runtime lifecycle
    with AEGISRuntime(db_path="/tmp/audit.db") as runtime:
        # ... configure runtime ...
        response = runtime.gateway.submit(request)
        # shutdown() is called automatically on exit
"""

from __future__ import annotations

from .audit import AuditSystem
from .capability_registry import CapabilityRegistry
from .decision_engine import DecisionEngine
from .gateway import GovernanceGateway
from .policy_engine import PolicyEngine
from .risk import RiskEngine
from .tool_proxy import ToolProxy


class AEGISRuntime:
    """A fully assembled AEGIS governance runtime.

    Each component is publicly accessible so that callers can configure
    capabilities and policies directly, while the plumbing (audit,
    decision engine, gateway) is set up automatically.

    The runtime can be used as a context manager for automatic resource
    cleanup::

        with AEGISRuntime() as runtime:
            # ... use runtime ...
            pass  # shutdown() called automatically

    Parameters
    ----------
    db_path : str
        SQLite database path for the :class:`~aegis.audit.AuditSystem`.
        Defaults to ``":memory:"`` (in-process, no persistence).
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        self._audit = AuditSystem(db_path=db_path)
        self._capabilities = CapabilityRegistry()
        self._policies = PolicyEngine()
        self._risk = RiskEngine(audit_system=self._audit)
        self._decision_engine = DecisionEngine(
            capability_registry=self._capabilities,
            policy_engine=self._policies,
            audit_system=self._audit,
            risk_engine=self._risk,
        )
        self._gateway = GovernanceGateway(decision_engine=self._decision_engine)
        self._is_shutdown = False

    # ------------------------------------------------------------------
    # File-based configuration (RFC-0005 RDP-03)
    # ------------------------------------------------------------------

    @classmethod
    def from_config(
        cls,
        registry: str | None = None,
        *,
        audit_db: str = ":memory:",
    ) -> AEGISRuntime:
        """Build a runtime from on-disk configuration files.

        This is the RFC-0005 RDP-03 (Embedded Lightweight) entry point:
        a single call that instantiates a runtime and loads its capability
        registry from a ``registry.json`` file. It is equivalent to::

            rt = AEGISRuntime(db_path=audit_db)
            if registry is not None:
                rt.capabilities.load_from_json(registry)

        but is provided as a classmethod so RDP-03 reference deployments
        can be a single line of setup.

        Parameters
        ----------
        registry : str or path-like, optional
            Path to a ``registry.json`` file. If ``None``, the runtime is
            instantiated with an empty capability registry (default-deny
            posture). See
            :meth:`CapabilityRegistry.load_from_json` for the file format.
        audit_db : str, optional
            SQLite database path for the audit system. Defaults to
            ``":memory:"`` (in-process, no persistence). For RDP-03
            deployments the caller will typically pass a filesystem path
            such as ``/var/lib/aegis/audit.sqlite`` or the sentinel for an
            append-only JSONL sink configured separately.

        Returns
        -------
        AEGISRuntime
            A fully-assembled runtime with capabilities loaded (if a
            registry file was supplied) and policies still empty. Callers
            are responsible for adding policies via ``rt.policies.add_policy``
            or a future policies.json loader (see changelog v0.1.3 for the
            current scope of file-based loading).

        Raises
        ------
        FileNotFoundError
            If ``registry`` is supplied and does not point to an existing
            file.
        ValueError
            If ``registry`` is supplied and the file is malformed (see
            :meth:`CapabilityRegistry.load_from_json` for specifics).
        """
        rt = cls(db_path=audit_db)
        if registry is not None:
            rt.capabilities.load_from_json(registry)
        return rt

    # ------------------------------------------------------------------
    # Context manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> AEGISRuntime:
        """Enter a context manager block.

        Returns
        -------
        AEGISRuntime
            Self, for use in ``with`` statements.
        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Exit a context manager block.

        Automatically calls :meth:`shutdown` to clean up resources.

        Parameters
        ----------
        exc_type
            Exception type if an exception occurred, else None.
        exc_val
            Exception value if an exception occurred, else None.
        exc_tb
            Exception traceback if an exception occurred, else None.
        """
        self.shutdown()

    def shutdown(self) -> None:
        """Shut down the runtime and clean up resources.

        This method:
        - Closes database connections
        - Clears in-memory state
        - Removes dangling resources

        This is called automatically if used as a context manager.
        Safe to call multiple times.
        """
        if self._is_shutdown:
            return

        # L-6: Use public close() method instead of accessing _conn
        import contextlib

        with contextlib.suppress(Exception):
            self._audit.close()

        # Mark as shutdown
        self._is_shutdown = True

    # ------------------------------------------------------------------
    # Public component accessors
    # ------------------------------------------------------------------

    @property
    def capabilities(self) -> CapabilityRegistry:
        """The :class:`~aegis.capability_registry.CapabilityRegistry`."""
        return self._capabilities

    @property
    def policies(self) -> PolicyEngine:
        """The :class:`~aegis.policy_engine.PolicyEngine`."""
        return self._policies

    @property
    def risk(self) -> RiskEngine:
        """The :class:`~aegis.risk.RiskEngine`."""
        return self._risk

    @property
    def audit(self) -> AuditSystem:
        """The :class:`~aegis.audit.AuditSystem`."""
        return self._audit

    @property
    def gateway(self) -> GovernanceGateway:
        """The :class:`~aegis.gateway.GovernanceGateway`."""
        return self._gateway

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def create_tool_proxy(self, agent_id: str, session_id: str) -> ToolProxy:
        """Create a :class:`~aegis.tool_proxy.ToolProxy` bound to this runtime.

        Parameters
        ----------
        agent_id : str
            The AI agent that will use the proxy.
        session_id : str
            The current session identifier.

        Returns
        -------
        ToolProxy
            A governance-enabled tool proxy for the agent.
        """
        return ToolProxy(
            gateway=self._gateway,
            agent_id=agent_id,
            session_id=session_id,
            audit_system=self._audit,
        )
