"""Tests for aegis_core.governance.profile.

Covers:

* Loader validation — basic schema and AEGIS extensions
* Compiler output shape — Cedar and Rego, basic-only and extension cases
* Determinism — same input produces byte-identical output
* Subset parity — when no extensions are set, the output body matches the
  shape published in the standalone AGT example contribution. The frozen
  expected outputs in ``TestSubsetParity`` are the contract: any change
  to the shared compiler shape must be reflected in BOTH this aegis-core
  module and the standalone AGT example. The test fails on drift.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from aegis_core.governance import (
    Capabilities,
    DelegationRules,
    GovernanceProfile,
    Principal,
    ProfileError,
    ProfileMetadata,
    ResourceScopes,
    compile_to_cedar,
    compile_to_rego,
    load_profile_from_dict,
    load_profile_from_yaml,
    snake_to_pascal,
)

# ── Test fixtures ─────────────────────────────────────────────


def _basic_profile_dict() -> dict[str, Any]:
    """Minimal valid profile with no AEGIS extensions."""
    return {
        "profile": {
            "id": "research-agent-standard",
            "version": "1.0.0",
            "description": "Standard governance profile for research-class agents",
        },
        "principal": {"role": "researcher"},
        "capabilities": {
            "allowed_actions": ["web_search", "document_read"],
            "denied_actions": ["file_write", "shell_exec"],
        },
        "resource_scopes": {
            "allowed_patterns": ["public/*", "research/published/*"],
            "denied_patterns": ["customer/pii/*", "internal/confidential/*"],
        },
    }


def _extension_profile_dict() -> dict[str, Any]:
    """Profile exercising every AEGIS extension."""
    raw = _basic_profile_dict()
    raw["atx1_techniques"] = ["ATX-1.T-2-3", "ATX-1.T-7-1"]
    raw["agp_trace_id"] = "agp1:profile:research-agent-standard:1.0.0"
    raw["delegation"] = {
        "max_depth": 2,
        "may_delegate_to": ["role:summarizer", "role:fact_checker"],
    }
    return raw


# ── Loader: basic schema ──────────────────────────────────────


class TestLoaderBasic:
    def test_loads_basic_profile(self) -> None:
        p = load_profile_from_dict(_basic_profile_dict())
        assert p.metadata.profile_id == "research-agent-standard"
        assert p.principal.role == "researcher"
        assert "web_search" in p.capabilities.allowed_actions
        assert "file_write" in p.capabilities.denied_actions
        assert p.atx1_techniques == ()
        assert p.agp_trace_id is None
        assert p.delegation is None

    def test_rejects_missing_required_block(self) -> None:
        raw = _basic_profile_dict()
        del raw["principal"]
        with pytest.raises(ProfileError, match="missing required key 'principal'"):
            load_profile_from_dict(raw)

    def test_rejects_overlapping_actions(self) -> None:
        raw = _basic_profile_dict()
        raw["capabilities"]["denied_actions"] = ["web_search", "shell_exec"]
        with pytest.raises(ProfileError, match="overlap"):
            load_profile_from_dict(raw)

    def test_rejects_overlapping_patterns(self) -> None:
        raw = _basic_profile_dict()
        raw["resource_scopes"]["denied_patterns"].append("public/*")
        with pytest.raises(ProfileError, match="overlap"):
            load_profile_from_dict(raw)

    def test_rejects_non_snake_case_action(self) -> None:
        raw = _basic_profile_dict()
        raw["capabilities"]["allowed_actions"] = ["WebSearch"]
        with pytest.raises(ProfileError, match="snake_case"):
            load_profile_from_dict(raw)

    def test_rejects_non_snake_case_role(self) -> None:
        raw = _basic_profile_dict()
        raw["principal"]["role"] = "Researcher"
        with pytest.raises(ProfileError, match="snake_case"):
            load_profile_from_dict(raw)

    def test_rejects_pattern_without_glob_suffix(self) -> None:
        raw = _basic_profile_dict()
        raw["resource_scopes"]["allowed_patterns"] = ["public"]
        with pytest.raises(ProfileError, match="prefix glob"):
            load_profile_from_dict(raw)

    def test_rejects_empty_action_list(self) -> None:
        raw = _basic_profile_dict()
        raw["capabilities"]["allowed_actions"] = []
        with pytest.raises(ProfileError, match="must be non-empty"):
            load_profile_from_dict(raw)

    def test_rejects_duplicate_action(self) -> None:
        raw = _basic_profile_dict()
        raw["capabilities"]["allowed_actions"] = ["web_search", "web_search"]
        with pytest.raises(ProfileError, match="duplicate"):
            load_profile_from_dict(raw)


# ── Loader: AEGIS extensions ──────────────────────────────────


class TestLoaderExtensions:
    def test_loads_full_extensions(self) -> None:
        p = load_profile_from_dict(_extension_profile_dict())
        assert p.atx1_techniques == ("ATX-1.T-2-3", "ATX-1.T-7-1")
        assert p.agp_trace_id == "agp1:profile:research-agent-standard:1.0.0"
        assert p.delegation is not None
        assert p.delegation.max_depth == 2
        assert p.delegation.may_delegate_to == ("role:summarizer", "role:fact_checker")

    def test_rejects_invalid_atx1_technique_id(self) -> None:
        raw = _basic_profile_dict()
        raw["atx1_techniques"] = ["T2"]
        with pytest.raises(ProfileError, match="ATX-1 technique ID"):
            load_profile_from_dict(raw)

    def test_rejects_duplicate_atx1_technique(self) -> None:
        raw = _basic_profile_dict()
        raw["atx1_techniques"] = ["ATX-1.T-2-3", "ATX-1.T-2-3"]
        with pytest.raises(ProfileError, match="duplicate"):
            load_profile_from_dict(raw)

    def test_rejects_negative_delegation_depth(self) -> None:
        raw = _basic_profile_dict()
        raw["delegation"] = {"max_depth": -1, "may_delegate_to": []}
        with pytest.raises(ProfileError, match="non-negative integer"):
            load_profile_from_dict(raw)

    def test_rejects_bool_delegation_depth(self) -> None:
        raw = _basic_profile_dict()
        raw["delegation"] = {"max_depth": True, "may_delegate_to": []}
        with pytest.raises(ProfileError, match="must be int"):
            load_profile_from_dict(raw)

    def test_rejects_unprefixed_delegation_role(self) -> None:
        raw = _basic_profile_dict()
        raw["delegation"] = {
            "max_depth": 1,
            "may_delegate_to": ["summarizer"],  # missing role: prefix
        }
        with pytest.raises(ProfileError, match="role:<snake_case>"):
            load_profile_from_dict(raw)

    def test_empty_agp_trace_id_rejected(self) -> None:
        raw = _basic_profile_dict()
        raw["agp_trace_id"] = "   "
        with pytest.raises(ProfileError, match="non-empty"):
            load_profile_from_dict(raw)

    def test_extensions_are_optional(self) -> None:
        # Each extension can be absent independently.
        raw = _basic_profile_dict()
        raw["atx1_techniques"] = ["ATX-1.T-1-1"]
        p = load_profile_from_dict(raw)
        assert p.atx1_techniques == ("ATX-1.T-1-1",)
        assert p.agp_trace_id is None
        assert p.delegation is None


# ── Loader: YAML ──────────────────────────────────────────────


class TestLoaderYaml:
    def test_loads_yaml_file(self, tmp_path: Path) -> None:
        yaml_text = (
            "profile:\n"
            "  id: research-agent-standard\n"
            '  version: "1.0.0"\n'
            "  description: Standard governance profile for research-class agents\n"
            "principal:\n"
            "  role: researcher\n"
            "capabilities:\n"
            "  allowed_actions:\n"
            "    - web_search\n"
            "  denied_actions:\n"
            "    - file_write\n"
            "resource_scopes:\n"
            '  allowed_patterns: ["public/*"]\n'
            '  denied_patterns: ["customer/pii/*"]\n'
        )
        yaml_path = tmp_path / "profile.yaml"
        yaml_path.write_text(yaml_text)
        p = load_profile_from_yaml(yaml_path)
        assert p.metadata.profile_id == "research-agent-standard"
        assert p.principal.role == "researcher"

    def test_invalid_yaml_raises_profile_error(self, tmp_path: Path) -> None:
        yaml_path = tmp_path / "bad.yaml"
        yaml_path.write_text("profile: [unclosed\n")
        with pytest.raises(ProfileError, match="invalid YAML"):
            load_profile_from_yaml(yaml_path)


# ── Snake-to-PascalCase ────────────────────────────────────────


class TestSnakeToPascal:
    @pytest.mark.parametrize(
        "snake,pascal",
        [
            ("web_search", "WebSearch"),
            ("file_read", "FileRead"),
            ("send_external_email", "SendExternalEmail"),
            ("a", "A"),
            ("a_b_c", "ABC"),
        ],
    )
    def test_round_trip(self, snake: str, pascal: str) -> None:
        assert snake_to_pascal(snake) == pascal


# ── Cedar emission: basic ─────────────────────────────────────


class TestCompileToCedarBasic:
    def test_contains_profile_metadata_in_header(self) -> None:
        p = load_profile_from_dict(_basic_profile_dict())
        out = compile_to_cedar(p)
        assert "research-agent-standard" in out
        assert "v1.0.0" in out
        assert "DO NOT EDIT BY HAND" in out

    def test_each_allowed_action_emitted_as_pascal_case(self) -> None:
        p = load_profile_from_dict(_basic_profile_dict())
        out = compile_to_cedar(p)
        assert 'Action::"WebSearch"' in out
        assert 'Action::"DocumentRead"' in out

    def test_each_denied_action_in_forbid(self) -> None:
        p = load_profile_from_dict(_basic_profile_dict())
        out = compile_to_cedar(p)
        # Locate the explicit denied-actions forbid block by its comment header.
        marker = "// Forbid denied actions outright"
        assert marker in out
        denied_block = out[out.index(marker) :]
        assert 'Action::"FileWrite"' in denied_block
        assert 'Action::"ShellExec"' in denied_block

    def test_role_check_in_permit_when(self) -> None:
        p = load_profile_from_dict(_basic_profile_dict())
        out = compile_to_cedar(p)
        assert 'context.principal_role == "researcher"' in out

    def test_no_extension_header_when_absent(self) -> None:
        p = load_profile_from_dict(_basic_profile_dict())
        out = compile_to_cedar(p)
        assert "AEGIS extensions" not in out
        assert "ATX-1 techniques" not in out
        assert "AGP-1 trace id" not in out


# ── Rego emission: basic ──────────────────────────────────────


class TestCompileToRegoBasic:
    def test_contains_profile_metadata_in_header(self) -> None:
        p = load_profile_from_dict(_basic_profile_dict())
        out = compile_to_rego(p)
        assert "research-agent-standard" in out
        assert "v1.0.0" in out

    def test_uses_rego_v1_syntax(self) -> None:
        p = load_profile_from_dict(_basic_profile_dict())
        out = compile_to_rego(p)
        assert re.search(r"^import rego\.v1$", out, re.MULTILINE)
        assert re.search(r"^default allow := false$", out, re.MULTILINE)
        assert "allow if {" in out

    def test_emits_action_sets_and_pattern_arrays(self) -> None:
        p = load_profile_from_dict(_basic_profile_dict())
        out = compile_to_rego(p)
        assert "allowed_actions := {" in out
        assert "denied_actions := {" in out
        assert "allowed_resource_patterns := [" in out
        assert "denied_resource_patterns := [" in out

    def test_role_check_in_allow_rule(self) -> None:
        p = load_profile_from_dict(_basic_profile_dict())
        out = compile_to_rego(p)
        assert 'input.principal_role == "researcher"' in out

    def test_no_extension_header_when_absent(self) -> None:
        p = load_profile_from_dict(_basic_profile_dict())
        out = compile_to_rego(p)
        assert "AEGIS extensions" not in out
        assert "delegation_depth" not in out
        assert "exceeds_delegation_depth" not in out


# ── AEGIS extensions ──────────────────────────────────────────


class TestCedarExtensions:
    def test_atx1_techniques_appear_in_header(self) -> None:
        p = load_profile_from_dict(_extension_profile_dict())
        out = compile_to_cedar(p)
        assert "// --- AEGIS extensions ---" in out
        assert "ATX-1.T-2-3" in out
        assert "ATX-1.T-7-1" in out

    def test_agp_trace_id_in_header(self) -> None:
        p = load_profile_from_dict(_extension_profile_dict())
        out = compile_to_cedar(p)
        assert "agp1:profile:research-agent-standard:1.0.0" in out

    def test_delegation_emits_extra_forbid_block(self) -> None:
        p = load_profile_from_dict(_extension_profile_dict())
        out = compile_to_cedar(p)
        assert "delegation_depth" in out
        # The forbid block uses the delegation max_depth from the profile.
        assert "context.delegation_depth > 2" in out


class TestRegoExtensions:
    def test_atx1_techniques_appear_in_header(self) -> None:
        p = load_profile_from_dict(_extension_profile_dict())
        out = compile_to_rego(p)
        assert "# --- AEGIS extensions ---" in out
        assert "ATX-1.T-2-3" in out
        assert "ATX-1.T-7-1" in out

    def test_agp_trace_id_in_header(self) -> None:
        p = load_profile_from_dict(_extension_profile_dict())
        out = compile_to_rego(p)
        assert "agp1:profile:research-agent-standard:1.0.0" in out

    def test_delegation_emits_extra_rule_and_allow_precondition(self) -> None:
        p = load_profile_from_dict(_extension_profile_dict())
        out = compile_to_rego(p)
        assert "exceeds_delegation_depth if {" in out
        assert "input.delegation_depth > 2" in out
        # The base allow rule must reference the new precondition.
        allow_block = out.split("allow if {")[1].split("}")[0]
        assert "not exceeds_delegation_depth" in allow_block


# ── Determinism ───────────────────────────────────────────────


class TestDeterminism:
    def test_cedar_byte_identical_across_runs(self) -> None:
        raw = _extension_profile_dict()
        a = compile_to_cedar(load_profile_from_dict(raw))
        b = compile_to_cedar(load_profile_from_dict(raw))
        assert a == b

    def test_rego_byte_identical_across_runs(self) -> None:
        raw = _extension_profile_dict()
        a = compile_to_rego(load_profile_from_dict(raw))
        b = compile_to_rego(load_profile_from_dict(raw))
        assert a == b


# ── Subset parity (frozen reference) ──────────────────────────


# These reference outputs are the contract with the standalone AGT
# example contribution at examples/aegis-governance-profile/ in
# microsoft/agent-governance-toolkit. The two compilers must produce
# byte-identical bodies (modulo the "Generated by" attribution line)
# for a basic-only profile. If this test fails after a change to the
# emission code, update BOTH this file AND the standalone AGT example
# in lockstep — drifting is a regression.

_PARITY_PROFILE_DICT: dict[str, Any] = {
    "profile": {
        "id": "research-agent-standard",
        "version": "1.0.0",
        "description": "Standard governance profile for research-class agents",
    },
    "principal": {"role": "researcher"},
    "capabilities": {
        "allowed_actions": ["web_search", "document_read"],
        "denied_actions": ["file_write", "shell_exec"],
    },
    "resource_scopes": {
        "allowed_patterns": ["public/*"],
        "denied_patterns": ["customer/pii/*"],
    },
}


_EXPECTED_CEDAR_BODY = """\
// Permit allowed actions when principal role and resource scope match.
permit(
    principal,
    action in [
        Action::"WebSearch",
        Action::"DocumentRead"
    ],
    resource
)
when {
    context.principal_role == "researcher" &&
    (
        context.resource_path like "public/*"
    )
};

// Forbid denied actions outright (forbid overrides permit).
forbid(
    principal,
    action in [
        Action::"FileWrite",
        Action::"ShellExec"
    ],
    resource
);

// Forbid any action on denied resource paths.
forbid(
    principal,
    action,
    resource
)
when {
    context.resource_path like "customer/pii/*"
};
"""


_EXPECTED_REGO_BODY = """\
package agentos.aegis

import rego.v1

default allow := false

allowed_actions := {
    "web_search",
    "document_read",
}

denied_actions := {
    "file_write",
    "shell_exec",
}

allowed_resource_patterns := [
    "public/",
]

denied_resource_patterns := [
    "customer/pii/",
]

allow if {
    input.principal_role == "researcher"
    allowed_actions[input.tool_name]
    in_allowed_scope
    not in_denied_action
    not in_denied_scope
}

in_allowed_scope if {
    some prefix in allowed_resource_patterns
    startswith(input.resource_path, prefix)
}

in_denied_scope if {
    some prefix in denied_resource_patterns
    startswith(input.resource_path, prefix)
}

in_denied_action if {
    denied_actions[input.tool_name]
}
"""


class TestSubsetParity:
    """Frozen reference outputs guarding against drift from the AGT subset."""

    @staticmethod
    def _strip_attribution_header(text: str, comment_prefix: str) -> str:
        """Strip the source-attribution header (varies between compilers).

        The header is the leading run of comment lines plus any blank-line
        spacers immediately after; the body begins at the first non-blank,
        non-comment line.
        """
        lines = text.splitlines(keepends=True)
        index = 0
        # Skip leading comment lines.
        while index < len(lines) and lines[index].strip().startswith(comment_prefix):
            index += 1
        # Skip blank-line spacer(s) between header and body.
        while index < len(lines) and not lines[index].strip():
            index += 1
        return "".join(lines[index:])

    def test_cedar_body_matches_subset(self) -> None:
        out = compile_to_cedar(load_profile_from_dict(_PARITY_PROFILE_DICT))
        body = self._strip_attribution_header(out, "//")
        assert body == _EXPECTED_CEDAR_BODY

    def test_rego_body_matches_subset(self) -> None:
        out = compile_to_rego(load_profile_from_dict(_PARITY_PROFILE_DICT))
        body = self._strip_attribution_header(out, "#")
        assert body == _EXPECTED_REGO_BODY


# ── Round-trip with constructed profile ───────────────────────


class TestProgrammaticConstruction:
    def test_can_construct_profile_directly(self) -> None:
        # Verifies the data model is usable without going through the loader,
        # for callers that build profiles programmatically.
        profile = GovernanceProfile(
            metadata=ProfileMetadata(
                profile_id="programmatic", version="0.0.1", description="ad-hoc"
            ),
            principal=Principal(role="ad_hoc_role"),
            capabilities=Capabilities(
                allowed_actions=("a",),
                denied_actions=("b",),
            ),
            resource_scopes=ResourceScopes(
                allowed_patterns=("p/*",),
                denied_patterns=("q/*",),
            ),
            delegation=DelegationRules(max_depth=0, may_delegate_to=()),
        )
        out = compile_to_cedar(profile)
        assert 'Action::"A"' in out
        assert "delegation_depth > 0" in out
