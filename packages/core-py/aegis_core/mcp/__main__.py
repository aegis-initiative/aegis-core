"""AEGIS MCP Server — standalone entry point.

Start a governed MCP server over stdio::

    python -m aegis_core.mcp

The server exposes AEGIS governance tools to any MCP-compatible client
(Claude Code, Cursor, VS Code, etc.).  Configure it by adding this to
your MCP client's settings::

    {
      "mcpServers": {
        "aegis": {
          "command": "python",
          "args": ["-m", "aegis_core.mcp"]
        }
      }
    }

The server starts with a demo configuration that demonstrates all four
governance outcomes (ALLOW, DENY, ESCALATE, REQUIRE_CONFIRMATION).
"""

from __future__ import annotations

import argparse
import sys

from .. import (
    ActionType,
    AEGISRuntime,
    Capability,
    Policy,
    PolicyCondition,
    PolicyEffect,
)
from ..mcp_server import AEGISMCPServer


def _build_demo_runtime() -> AEGISRuntime:
    """Create a runtime with a demo governance configuration."""
    rt = AEGISRuntime()

    # Capabilities
    rt.capabilities.register(
        Capability(
            id="cap-file-read",
            name="file.read",
            description="Read files from governed paths",
            action_types=[ActionType.FILE_READ.value],
            target_patterns=["/home/*", "/data/*"],
        )
    )
    rt.capabilities.register(
        Capability(
            id="cap-file-write",
            name="file.write",
            description="Write files to governed paths",
            action_types=[ActionType.FILE_WRITE.value],
            target_patterns=["/home/*", "/data/*"],
        )
    )
    rt.capabilities.register(
        Capability(
            id="cap-network",
            name="network.fetch",
            description="Fetch from approved network endpoints",
            action_types=[ActionType.API_CALL.value],
            target_patterns=["https://*"],
        )
    )
    rt.capabilities.register(
        Capability(
            id="cap-shell",
            name="shell.exec",
            description="Execute shell commands (requires confirmation)",
            action_types=[ActionType.SHELL_EXEC.value],
            target_patterns=["*"],
        )
    )
    rt.capabilities.register(
        Capability(
            id="cap-tool",
            name="tool.call",
            description="Generic tool calls",
            action_types=[ActionType.TOOL_CALL.value],
            target_patterns=["*"],
        )
    )

    # Grant all capabilities to the default agent
    for cap_id in ("cap-file-read", "cap-file-write", "cap-network", "cap-shell", "cap-tool"):
        rt.capabilities.grant("mcp-agent", cap_id)

    # Policies
    rt.policies.add_policy(
        Policy(
            id="pol-allow-reads",
            name="Allow file reads",
            description="File reads in governed paths are allowed",
            effect=PolicyEffect.ALLOW,
            conditions=[
                PolicyCondition(
                    evaluate=lambda req: req.action.type == ActionType.FILE_READ,
                    description="action is file_read",
                )
            ],
            priority=200,
        )
    )
    rt.policies.add_policy(
        Policy(
            id="pol-deny-writes",
            name="Deny file writes",
            description="File writes are denied by policy",
            effect=PolicyEffect.DENY,
            conditions=[
                PolicyCondition(
                    evaluate=lambda req: req.action.type == ActionType.FILE_WRITE,
                    description="action is file_write",
                )
            ],
            priority=50,
        )
    )
    rt.policies.add_policy(
        Policy(
            id="pol-escalate-network",
            name="Escalate network requests",
            description="Network requests require elevated review",
            effect=PolicyEffect.ESCALATE,
            conditions=[
                PolicyCondition(
                    evaluate=lambda req: req.action.type == ActionType.API_CALL,
                    description="action is api_call",
                )
            ],
            priority=100,
        )
    )
    rt.policies.add_policy(
        Policy(
            id="pol-confirm-shell",
            name="Require confirmation for shell",
            description="Shell commands require human confirmation",
            effect=PolicyEffect.REQUIRE_CONFIRMATION,
            conditions=[
                PolicyCondition(
                    evaluate=lambda req: req.action.type == ActionType.SHELL_EXEC,
                    description="action is shell_exec",
                )
            ],
            priority=100,
        )
    )
    rt.policies.add_policy(
        Policy(
            id="pol-allow-tools",
            name="Allow tool calls",
            description="Generic tool calls are allowed",
            effect=PolicyEffect.ALLOW,
            conditions=[
                PolicyCondition(
                    evaluate=lambda req: req.action.type == ActionType.TOOL_CALL,
                    description="action is tool_call",
                )
            ],
            priority=200,
        )
    )

    return rt


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m aegis_core.mcp",
        description="AEGIS Governance MCP Server",
    )
    parser.add_argument(
        "--agent-id",
        default="mcp-agent",
        help="Default agent identity (default: mcp-agent)",
    )
    parser.add_argument(
        "--session-id",
        default="mcp-session",
        help="Default session identifier (default: mcp-session)",
    )
    args = parser.parse_args()

    # Log to stderr so stdout stays clean for JSON-RPC
    print("AEGIS Governance MCP Server starting...", file=sys.stderr)
    print(f"  Agent ID: {args.agent_id}", file=sys.stderr)
    print(f"  Session:  {args.session_id}", file=sys.stderr)
    print("  Mode:     demo (built-in governance configuration)", file=sys.stderr)
    print("  Ready for MCP client connections on stdio", file=sys.stderr)

    runtime = _build_demo_runtime()
    server = AEGISMCPServer(
        runtime,
        agent_id=args.agent_id,
        session_id=args.session_id,
    )
    server.run_stdio()


if __name__ == "__main__":
    main()
