"""Tests for the RFC-0005 RDP-03 file-based configuration loader.

Exercises ``Capability.from_dict``, ``Capability.to_dict``,
``CapabilityRegistry.load_from_json``, and ``AEGISRuntime.from_config``.
These are the building blocks of the "registry.json" reference deployment
pattern that aegis-core ships in v0.1.3.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aegis_core import AEGISRuntime
from aegis_core.capability_registry import Capability, CapabilityRegistry
from aegis_core.protocol import ActionType


# ---------------------------------------------------------------------------
# Capability.to_dict / from_dict
# ---------------------------------------------------------------------------


class TestCapabilityDictRoundTrip:
    """``to_dict`` / ``from_dict`` must be lossless for all supported fields."""

    def test_round_trip_minimal(self):
        original = Capability(
            id="cap-1",
            name="Minimal",
            description="Minimal cap",
            action_types=[ActionType.TOOL_CALL.value],
            target_patterns=["*"],
        )
        restored = Capability.from_dict(original.to_dict())
        assert restored.id == original.id
        assert restored.name == original.name
        assert restored.description == original.description
        assert restored.action_types == original.action_types
        assert restored.target_patterns == original.target_patterns
        assert restored.expires_at is None
        assert restored.metadata == {}

    def test_round_trip_full(self):
        original = Capability(
            id="cap-2",
            name="Full",
            description="All fields populated",
            action_types=[ActionType.FILE_READ.value, ActionType.FILE_WRITE.value],
            target_patterns=["/var/tmp/*", "/home/agent/*"],
            expires_at=datetime.now(UTC) + timedelta(days=1),
            metadata={"owner": "finnoybu", "tier": "high"},
        )
        restored = Capability.from_dict(original.to_dict())
        assert restored.action_types == original.action_types
        assert restored.target_patterns == original.target_patterns
        assert restored.expires_at is not None
        assert restored.metadata == {"owner": "finnoybu", "tier": "high"}


class TestCapabilityFromDictValidation:
    """Malformed registry entries must raise ``ValueError`` with a clear message."""

    def test_missing_required_field(self):
        with pytest.raises(ValueError, match="missing required field"):
            Capability.from_dict({
                "id": "cap",
                "name": "X",
                # missing description, action_types, target_patterns
            })

    def test_action_types_not_list(self):
        with pytest.raises(ValueError, match="action_types"):
            Capability.from_dict({
                "id": "cap",
                "name": "X",
                "description": "d",
                "action_types": "tool_call",  # string, not list
                "target_patterns": ["*"],
            })

    def test_target_patterns_non_string(self):
        with pytest.raises(ValueError, match="target_patterns"):
            Capability.from_dict({
                "id": "cap",
                "name": "X",
                "description": "d",
                "action_types": ["tool_call"],
                "target_patterns": [1, 2, 3],
            })

    def test_metadata_not_object(self):
        with pytest.raises(ValueError, match="metadata"):
            Capability.from_dict({
                "id": "cap",
                "name": "X",
                "description": "d",
                "action_types": ["tool_call"],
                "target_patterns": ["*"],
                "metadata": "not-a-dict",
            })


# ---------------------------------------------------------------------------
# CapabilityRegistry.load_from_json
# ---------------------------------------------------------------------------


def _write_registry(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


class TestLoadFromJSON:
    """End-to-end file loading into a fresh registry."""

    def test_load_capabilities_and_grants(self, tmp_path: Path):
        path = _write_registry(
            tmp_path,
            {
                "version": "1",
                "capabilities": [
                    {
                        "id": "fs.read.tmp",
                        "name": "Read /var/tmp",
                        "description": "Read files under /var/tmp",
                        "action_types": ["file_read"],
                        "target_patterns": ["/var/tmp/*"],
                    },
                    {
                        "id": "fs.write.tmp",
                        "name": "Write /var/tmp",
                        "description": "Write files under /var/tmp",
                        "action_types": ["file_write"],
                        "target_patterns": ["/var/tmp/*"],
                    },
                ],
                "grants": {
                    "agent-alice": ["fs.read.tmp", "fs.write.tmp"],
                    "agent-bob": ["fs.read.tmp"],
                },
            },
        )
        reg = CapabilityRegistry()
        reg.load_from_json(path)

        alice_caps = {c.id for c in reg.get_agent_capabilities("agent-alice")}
        bob_caps = {c.id for c in reg.get_agent_capabilities("agent-bob")}
        assert alice_caps == {"fs.read.tmp", "fs.write.tmp"}
        assert bob_caps == {"fs.read.tmp"}

    def test_load_without_grants_section(self, tmp_path: Path):
        path = _write_registry(
            tmp_path,
            {
                "version": "1",
                "capabilities": [
                    {
                        "id": "cap-1",
                        "name": "X",
                        "description": "",
                        "action_types": ["tool_call"],
                        "target_patterns": ["*"],
                    },
                ],
            },
        )
        reg = CapabilityRegistry()
        reg.load_from_json(path)
        # Capability is registered, but no agent has been granted it.
        assert reg.get_agent_capabilities("anyone") == []

    def test_missing_file_raises(self, tmp_path: Path):
        reg = CapabilityRegistry()
        with pytest.raises(FileNotFoundError, match="registry.json not found"):
            reg.load_from_json(tmp_path / "does-not-exist.json")

    def test_invalid_json_raises(self, tmp_path: Path):
        path = tmp_path / "registry.json"
        path.write_text("{not valid json", encoding="utf-8")
        reg = CapabilityRegistry()
        with pytest.raises(ValueError, match="not valid JSON"):
            reg.load_from_json(path)

    def test_missing_capabilities_field_raises(self, tmp_path: Path):
        path = _write_registry(tmp_path, {"version": "1"})
        reg = CapabilityRegistry()
        with pytest.raises(ValueError, match="'capabilities'"):
            reg.load_from_json(path)

    def test_grants_referencing_unknown_cap_raises(self, tmp_path: Path):
        path = _write_registry(
            tmp_path,
            {
                "version": "1",
                "capabilities": [
                    {
                        "id": "known",
                        "name": "X",
                        "description": "",
                        "action_types": ["tool_call"],
                        "target_patterns": ["*"],
                    },
                ],
                "grants": {
                    "agent-1": ["unknown-cap"],
                },
            },
        )
        reg = CapabilityRegistry()
        with pytest.raises(ValueError, match="unknown capability"):
            reg.load_from_json(path)

    def test_grants_non_list_raises(self, tmp_path: Path):
        path = _write_registry(
            tmp_path,
            {
                "version": "1",
                "capabilities": [],
                "grants": {"agent-1": "not-a-list"},
            },
        )
        reg = CapabilityRegistry()
        with pytest.raises(ValueError, match="list of capability IDs"):
            reg.load_from_json(path)


# ---------------------------------------------------------------------------
# AEGISRuntime.from_config
# ---------------------------------------------------------------------------


class TestFromConfig:
    """``AEGISRuntime.from_config`` is the RDP-03 one-line entry point."""

    def test_from_config_with_registry(self, tmp_path: Path):
        path = _write_registry(
            tmp_path,
            {
                "version": "1",
                "capabilities": [
                    {
                        "id": "tool.call.any",
                        "name": "Any tool call",
                        "description": "",
                        "action_types": ["tool_call"],
                        "target_patterns": ["*"],
                    },
                ],
                "grants": {"agent-1": ["tool.call.any"]},
            },
        )
        with AEGISRuntime.from_config(registry=path) as rt:
            caps = rt.capabilities.get_agent_capabilities("agent-1")
            assert len(caps) == 1
            assert caps[0].id == "tool.call.any"

    def test_from_config_without_registry_is_default_deny(self):
        # A runtime with no configuration must deny everything, matching
        # the invariant documented in §3.3 of the architectural docs.
        with AEGISRuntime.from_config() as rt:
            proxy = rt.create_tool_proxy("agent-x", "sess-1")
            proxy.register_tool("t", fn=lambda: None, target="t")
            with pytest.raises(PermissionError):
                proxy.call("t")

    def test_from_config_audit_db_path(self, tmp_path: Path):
        audit_path = tmp_path / "audit.sqlite"
        with AEGISRuntime.from_config(audit_db=str(audit_path)) as rt:
            # Nothing to assert about the DB contents here; we just want
            # to prove the parameter is plumbed through without crashing.
            assert rt.audit is not None
