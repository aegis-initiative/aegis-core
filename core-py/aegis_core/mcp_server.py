"""AEGIS MCP Server.

Exposes the AEGIS governance runtime as a Model Context Protocol (MCP)
server.  Any MCP-compatible AI agent (Claude Code, Cursor, etc.) can
connect and have its tool calls **transparently governed**.

The server implements JSON-RPC 2.0 over stdio, following the MCP
specification (2024-11-05).

Architecture
------------
AEGIS is the MCP server that wraps the agent's real tools.  The agent
sees its tools (``file.read``, ``shell.exec``, etc.) and calls them
normally — every call passes through the governance gateway before the
underlying tool executes.  If denied, the tool never runs.  The agent
has no bypass path.

**Enforcement is the default.**  The agent does not choose to be
governed — it is governed by the infrastructure it connects to.

Observability tools (``aegis_audit``, ``aegis_capabilities``,
``aegis_policies``) are always available so the agent can inspect the
governance state.  The ``aegis_propose`` tool is **optional** — enabled
only when the operator wants governance-aware agents to proactively
check actions before attempting them.

Usage (standalone)::

    python -m aegis_core.mcp

Usage (embedded)::

    from aegis_core import AEGISRuntime
    from aegis_core.mcp_server import AEGISMCPServer

    runtime = AEGISRuntime()
    # ... configure capabilities and policies ...
    server = AEGISMCPServer(runtime, agent_id="my-agent")
    server.register_tool("file_read", fn=read_fn, target="/data/*")
    server.run_stdio()

Zero external dependencies — stdlib only.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from typing import Any

from .protocol import ActionType, AGPAction, AGPContext, AGPRequest, Decision
from .runtime import AEGISRuntime

# MCP protocol version
_PROTOCOL_VERSION = "2024-11-05"


class AEGISMCPServer:
    """MCP server backed by an AEGIS governance runtime.

    Registered tools are transparently governed — the agent calls them
    normally, and AEGIS evaluates every call before execution.

    Parameters
    ----------
    runtime : AEGISRuntime
        The governance runtime to use for evaluation.
    agent_id : str
        Default agent identity for governance proposals.
    session_id : str, optional
        Default session identifier.  Auto-generated if omitted.
    expose_propose : bool, optional
        If True, expose the ``aegis_propose`` tool so governance-aware
        agents can proactively check actions.  **Default is False** —
        enforcement is transparent, not voluntary.
    """

    def __init__(
        self,
        runtime: AEGISRuntime,
        agent_id: str = "mcp-agent",
        session_id: str = "mcp-session",
        *,
        expose_propose: bool = False,
    ) -> None:
        self._runtime = runtime
        self._agent_id = agent_id
        self._session_id = session_id
        self._proxy = runtime.create_tool_proxy(agent_id, session_id)
        self._initialized = False
        self._expose_propose = expose_propose

        # External tools registered for governed execution
        self._external_tools: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Tool registration
    # ------------------------------------------------------------------

    def register_tool(
        self,
        name: str,
        fn: Callable[..., Any],
        description: str = "",
        target: str = "",
        input_schema: dict[str, Any] | None = None,
    ) -> None:
        """Register an external tool for governed MCP execution.

        Parameters
        ----------
        name : str
            Tool name exposed to MCP clients.
        fn : callable
            The function to execute when the tool is called.
        description : str
            Human-readable description of what the tool does.
        target : str
            Governance target string.  Defaults to *name*.
        input_schema : dict, optional
            JSON Schema for the tool's input parameters.
        """
        self._proxy.register_tool(name, fn=fn, target=target or name)
        self._external_tools[name] = {
            "name": name,
            "description": description or f"Governed tool: {name}",
            "inputSchema": input_schema or {
                "type": "object",
                "properties": {},
            },
        }

    # ------------------------------------------------------------------
    # MCP tool definitions (built-in governance tools)
    # ------------------------------------------------------------------

    def _builtin_tools(self) -> list[dict[str, Any]]:
        """Return MCP tool definitions for built-in governance tools.

        Observability tools (audit, capabilities, policies) are always
        exposed.  The ``aegis_propose`` tool is only included when the
        operator has explicitly enabled it via ``expose_propose=True``.
        """
        tools: list[dict[str, Any]] = []

        # Optional: voluntary governance proposal (off by default)
        if self._expose_propose:
            tools.append({
                "name": "aegis_propose",
                "description": (
                    "Submit an action proposal to the AEGIS governance "
                    "engine and receive a decision (ALLOW, DENY, ESCALATE, "
                    "or REQUIRE_CONFIRMATION). This is an optional "
                    "pre-check — enforcement happens transparently on "
                    "every tool call regardless."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "capability": {
                            "type": "string",
                            "description": (
                                "The capability/action type being requested "
                                "(e.g. file.read, shell.exec, network.fetch)"
                            ),
                        },
                        "resource": {
                            "type": "string",
                            "description": "The target resource (file path, URL, command)",
                        },
                        "parameters": {
                            "type": "object",
                            "description": "Additional parameters for the action",
                            "default": {},
                        },
                    },
                    "required": ["capability", "resource"],
                },
            })

        tools.extend([
            {
                "name": "aegis_capabilities",
                "description": (
                    "List all capabilities registered in the AEGIS "
                    "governance runtime."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
            {
                "name": "aegis_audit",
                "description": (
                    "Query the AEGIS governance audit log for recent "
                    "decisions."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of records to return",
                            "default": 20,
                        },
                        "agent_id": {
                            "type": "string",
                            "description": "Filter by agent ID (optional)",
                        },
                    },
                },
            },
            {
                "name": "aegis_policies",
                "description": (
                    "List all governance policies registered in the AEGIS "
                    "runtime."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
        ])

        return tools

    # ------------------------------------------------------------------
    # Tool execution
    # ------------------------------------------------------------------

    def _handle_aegis_propose(self, arguments: dict[str, Any]) -> str:
        """Execute the aegis_propose tool (only available when expose_propose=True)."""
        capability = arguments.get("capability", "")
        resource = arguments.get("resource", "")
        parameters = arguments.get("parameters", {})

        # Map capability string to ActionType
        cap_map: dict[str, ActionType] = {
            "file.read": ActionType.FILE_READ,
            "file.write": ActionType.FILE_WRITE,
            "network.fetch": ActionType.API_CALL,
            "database.query": ActionType.DATA_ACCESS,
            "shell.exec": ActionType.SHELL_EXEC,
            "tool.call": ActionType.TOOL_CALL,
        }
        action_type = cap_map.get(capability, ActionType.TOOL_CALL)

        request = AGPRequest(
            agent_id=self._agent_id,
            action=AGPAction(
                type=action_type,
                target=resource,
                parameters=parameters,
            ),
            context=AGPContext(session_id=self._session_id),
        )

        try:
            response = self._runtime.gateway.submit(request)
        except Exception as exc:
            return json.dumps({
                "outcome": "ERROR",
                "reason": str(exc),
            })

        outcome_map = {
            Decision.APPROVED: "ALLOW",
            Decision.DENIED: "DENY",
            Decision.ESCALATE: "ESCALATE",
            Decision.REQUIRE_CONFIRMATION: "REQUIRE_CONFIRMATION",
        }

        return json.dumps({
            "decision_id": response.request_id,
            "outcome": outcome_map.get(response.decision, response.decision.value),
            "reason": response.reason,
            "risk_score": response.risk_score,
            "audit_ref": response.audit_id,
        })

    def _handle_aegis_capabilities(self, arguments: dict[str, Any]) -> str:
        """Execute the aegis_capabilities tool."""
        caps = []
        for cap in self._runtime.capabilities.get_agent_capabilities(self._agent_id):
            caps.append({
                "id": cap.id,
                "name": cap.name,
                "description": cap.description,
                "action_types": cap.action_types,
                "target_patterns": cap.target_patterns,
            })
        return json.dumps({"capabilities": caps, "count": len(caps)})

    def _handle_aegis_audit(self, arguments: dict[str, Any]) -> str:
        """Execute the aegis_audit tool."""
        limit = arguments.get("limit", 20)
        agent_id = arguments.get("agent_id")

        if agent_id:
            records = self._runtime.audit.get_agent_history(agent_id, limit=limit)
        else:
            # Get recent records across all agents
            with self._runtime.audit._lock:
                cursor = self._runtime.audit._conn.execute(
                    "SELECT * FROM audit_records ORDER BY rowid DESC LIMIT ?",
                    (limit,),
                )
                rows = cursor.fetchall()
            records = [self._runtime.audit._row_to_record(row) for row in rows]

        events = [
            {
                "id": r.id,
                "agent_id": r.agent_id,
                "action_type": r.action_type,
                "target": r.action_target,
                "decision": r.decision,
                "reason": r.reason,
                "timestamp": r.timestamp,
            }
            for r in records
        ]
        return json.dumps({"events": events, "count": len(events)})

    def _handle_aegis_policies(self, arguments: dict[str, Any]) -> str:
        """Execute the aegis_policies tool."""
        policies = self._runtime.policies.list_policies()
        items = [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "effect": p.effect.value,
                "priority": p.priority,
                "enabled": p.enabled,
            }
            for p in policies
        ]
        return json.dumps({"policies": items, "count": len(items)})

    def _handle_external_tool(self, name: str, arguments: dict[str, Any]) -> str:
        """Execute a registered external tool through governance."""
        try:
            result = self._proxy.call(name, **arguments)
            if isinstance(result, str):
                return result
            return json.dumps(result) if result is not None else "OK"
        except PermissionError as exc:
            return json.dumps({"error": "denied", "reason": str(exc)})
        except ValueError as exc:
            return json.dumps({"error": "invalid", "reason": str(exc)})
        except Exception as exc:
            return json.dumps({"error": "execution_failed", "reason": str(exc)})

    # ------------------------------------------------------------------
    # JSON-RPC 2.0 dispatch
    # ------------------------------------------------------------------

    def _handle_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Process a single JSON-RPC 2.0 message.

        Returns a response dict, or None for notifications.
        """
        method = message.get("method", "")
        params = message.get("params", {})
        msg_id = message.get("id")

        # Notifications (no id) — don't return a response
        if msg_id is None:
            if method == "notifications/initialized":
                self._initialized = True
            return None

        # Methods that require a response
        if method == "initialize":
            return self._rpc_result(msg_id, {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {},
                },
                "serverInfo": {
                    "name": "aegis-governance",
                    "version": "0.2.0",
                },
            })

        if method == "tools/list":
            tools = self._builtin_tools() + [
                self._external_tools[name]
                for name in self._external_tools
            ]
            return self._rpc_result(msg_id, {"tools": tools})

        if method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})

            # Built-in observability tools (always available)
            handlers: dict[str, Any] = {
                "aegis_capabilities": self._handle_aegis_capabilities,
                "aegis_audit": self._handle_aegis_audit,
                "aegis_policies": self._handle_aegis_policies,
            }
            # Optional: voluntary proposal tool (off by default)
            if self._expose_propose:
                handlers["aegis_propose"] = self._handle_aegis_propose

            if tool_name in handlers:
                try:
                    text = handlers[tool_name](arguments)
                except Exception as exc:
                    return self._rpc_error(msg_id, -32603, str(exc))
                return self._rpc_result(msg_id, {
                    "content": [{"type": "text", "text": text}],
                })

            # External governed tools
            if tool_name in self._external_tools:
                try:
                    text = self._handle_external_tool(tool_name, arguments)
                except Exception as exc:
                    return self._rpc_error(msg_id, -32603, str(exc))
                return self._rpc_result(msg_id, {
                    "content": [{"type": "text", "text": text}],
                })

            return self._rpc_error(
                msg_id, -32601, f"Unknown tool: {tool_name}"
            )

        if method == "ping":
            return self._rpc_result(msg_id, {})

        return self._rpc_error(msg_id, -32601, f"Method not found: {method}")

    # ------------------------------------------------------------------
    # JSON-RPC helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _rpc_result(msg_id: Any, result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    @staticmethod
    def _rpc_error(msg_id: Any, code: int, message: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": code, "message": message},
        }

    # ------------------------------------------------------------------
    # Transport: stdio
    # ------------------------------------------------------------------

    def run_stdio(self) -> None:
        """Run the MCP server over stdin/stdout.

        Reads JSON-RPC messages from stdin (one per line) and writes
        responses to stdout.  Runs until stdin is closed or EOF.
        """
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                response = self._rpc_error(None, -32700, "Parse error")
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
                continue

            response = self._handle_message(message)
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
