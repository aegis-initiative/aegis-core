"""AEGIS Governance Profile compiler — declarative authorization for AGP-1.

Compiles a single declarative *governance profile* (YAML or dict) into
equivalent Cedar and Rego policies suitable for downstream policy
engines (AWS Cedar, OPA / Rego). The profile is the authorship surface
governance and compliance stakeholders work in — role, capabilities,
resource scopes, optional delegation rules — and the compiler produces
idiomatic policy text in both target languages.

Role in AGP-1
-------------
Profiles are not themselves an AGP-1 message type. They describe the
authorization intent enforced *upstream of AGP-1*, at the external
policy backend layer. When AEGIS-extended fields are present
(``atx1_techniques``, ``agp_trace_id``, ``delegation``), the emitted
policies include audit metadata that links enforcement decisions back
to AEGIS spec artifacts (ATX-1 technique IDs, AGP-1 trace records).

Standalone subset
-----------------
A standalone, AEGIS-independent copy of the *core* compiler is published
as a community example contribution to Microsoft's Agent Governance
Toolkit at ``examples/aegis-governance-profile/`` in
``microsoft/agent-governance-toolkit``. The two compilers are
output-identical for the basic profile schema; this version adds
opt-in extensions for ecosystem traceability. When all extension
fields are absent (the default), the compiler output is byte-identical
to the standalone subset. This invariant is verified by
``tests/governance/test_profile.py::TestSubsetParity``.

Schema (AEGIS profile v1)
-------------------------
Basic fields (also present in the standalone AGT subset)::

    profile:
      id: <string>
      version: <string>
      description: <string>

    principal:
      role: <snake_case_string>

    capabilities:
      allowed_actions: [<snake_case>, ...]
      denied_actions:  [<snake_case>, ...]

    resource_scopes:
      allowed_patterns: [<prefix_glob>, ...]
      denied_patterns:  [<prefix_glob>, ...]

AEGIS extension fields (this implementation only)::

    atx1_techniques: ["ATX-1.T-2-3", "ATX-1.T-7-1", ...]
    agp_trace_id: "agp1:profile:research-agent-standard:1.0.0"
    delegation:
      max_depth: 2
      may_delegate_to: ["role:summarizer", ...]

Extensions appear as informational comments / additional rules in the
emitted Cedar and Rego; basic field semantics are unchanged.

Calling convention (consumer side)
----------------------------------
The emitted policies expect the policy-evaluator's request context to
provide two discriminator fields in addition to standard ``tool_name``
/ ``agent_id``:

* ``principal_role`` — compared against the profile's ``principal.role``
* ``resource_path`` — matched against allowed / denied scope patterns

In Cedar these appear under ``context.<field>``; in Rego under
``input.<field>``.

YAML loading
------------
Loading from YAML requires PyYAML. To keep aegis-core's zero-dependency
core, ``load_profile_from_yaml`` imports yaml lazily and raises a
clear error if PyYAML is not installed. Install via the optional
extra::

    pip install aegis-core[governance]

For dict-based loading (no external dependency), use
``load_profile_from_dict``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "Capabilities",
    "DelegationRules",
    "GovernanceProfile",
    "Principal",
    "ProfileError",
    "ProfileMetadata",
    "ResourceScopes",
    "compile_to_cedar",
    "compile_to_rego",
    "load_profile_from_dict",
    "load_profile_from_yaml",
    "snake_to_pascal",
]

PROFILE_SCHEMA_VERSION = "v1"


# ── Data model ────────────────────────────────────────────────


@dataclass(frozen=True)
class ProfileMetadata:
    profile_id: str
    version: str
    description: str


@dataclass(frozen=True)
class Principal:
    role: str


@dataclass(frozen=True)
class Capabilities:
    allowed_actions: tuple[str, ...]
    denied_actions: tuple[str, ...]


@dataclass(frozen=True)
class ResourceScopes:
    allowed_patterns: tuple[str, ...]
    denied_patterns: tuple[str, ...]


@dataclass(frozen=True)
class DelegationRules:
    """AEGIS extension: declarative delegation constraints.

    ``max_depth`` caps the principal-chain depth at which the profile
    still applies (0 = direct invocation only; 1 = one delegated hop).
    ``may_delegate_to`` is the allow-list of principal roles a profile
    holder may delegate to (prefixed ``role:`` matches the
    ``principal.role`` of the receiving profile).
    """

    max_depth: int
    may_delegate_to: tuple[str, ...]


@dataclass(frozen=True)
class GovernanceProfile:
    """Loaded and validated governance profile.

    The first four fields constitute the *basic schema* shared with
    the standalone AGT example. The remaining three are AEGIS-only
    extensions; when all are unset (the default), the compiler output
    is byte-identical to the standalone version.
    """

    metadata: ProfileMetadata
    principal: Principal
    capabilities: Capabilities
    resource_scopes: ResourceScopes
    # AEGIS extensions — opt-in
    atx1_techniques: tuple[str, ...] = ()
    agp_trace_id: str | None = None
    delegation: DelegationRules | None = None


# ── Errors ────────────────────────────────────────────────────


class ProfileError(ValueError):
    """Raised when a profile fails schema or semantic validation."""


# ── Loaders ───────────────────────────────────────────────────


def load_profile_from_yaml(path: Path | str) -> GovernanceProfile:
    """Load and validate a profile from a YAML file.

    Requires PyYAML (install via ``aegis-core[governance]``).

    Raises:
        ProfileError: if the YAML is invalid or fails schema validation.
        ImportError: if PyYAML is not installed.
    """
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover — guard for optional dep
        raise ImportError(
            "PyYAML is required to load profiles from YAML. "
            "Install via: pip install aegis-core[governance]"
        ) from exc

    file_path = Path(path)
    try:
        raw = yaml.safe_load(file_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ProfileError(f"{file_path}: invalid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise ProfileError(f"{file_path}: top-level must be a mapping")

    return _build_profile(raw, source=str(file_path))


def load_profile_from_dict(
    raw: Mapping[str, Any], *, source: str = "<dict>"
) -> GovernanceProfile:
    """Load and validate a profile from an in-memory mapping.

    Useful when the profile source is already parsed (JSON, programmatic
    construction, configuration store) and avoids the optional PyYAML
    dependency.
    """
    return _build_profile(dict(raw), source=source)


def _build_profile(raw: dict[str, Any], *, source: str) -> GovernanceProfile:
    metadata = _build_metadata(_require(raw, "profile", source, dict), source)
    principal = _build_principal(_require(raw, "principal", source, dict), source)
    capabilities = _build_capabilities(
        _require(raw, "capabilities", source, dict), source
    )
    resource_scopes = _build_resource_scopes(
        _require(raw, "resource_scopes", source, dict), source
    )

    overlap = set(capabilities.allowed_actions) & set(capabilities.denied_actions)
    if overlap:
        raise ProfileError(
            f"{source}: capabilities.allowed_actions and capabilities.denied_actions "
            f"overlap: {sorted(overlap)}"
        )

    pattern_overlap = set(resource_scopes.allowed_patterns) & set(
        resource_scopes.denied_patterns
    )
    if pattern_overlap:
        raise ProfileError(
            f"{source}: resource_scopes.allowed_patterns and "
            f"resource_scopes.denied_patterns overlap: {sorted(pattern_overlap)}"
        )

    atx1_techniques = _build_atx1_techniques(raw, source)
    agp_trace_id = _build_agp_trace_id(raw, source)
    delegation = _build_delegation(raw, source)

    return GovernanceProfile(
        metadata=metadata,
        principal=principal,
        capabilities=capabilities,
        resource_scopes=resource_scopes,
        atx1_techniques=atx1_techniques,
        agp_trace_id=agp_trace_id,
        delegation=delegation,
    )


def _build_metadata(raw: dict[str, Any], source: str) -> ProfileMetadata:
    return ProfileMetadata(
        profile_id=_require_str(raw, "id", f"{source}:profile"),
        version=_require_str(raw, "version", f"{source}:profile"),
        description=_require_str(raw, "description", f"{source}:profile"),
    )


def _build_principal(raw: dict[str, Any], source: str) -> Principal:
    role = _require_str(raw, "role", f"{source}:principal")
    if not _is_snake_case(role):
        raise ProfileError(
            f"{source}:principal.role must be snake_case, got {role!r}"
        )
    return Principal(role=role)


def _build_capabilities(raw: dict[str, Any], source: str) -> Capabilities:
    allowed = _require_action_list(raw, "allowed_actions", f"{source}:capabilities")
    denied = _require_action_list(raw, "denied_actions", f"{source}:capabilities")
    return Capabilities(allowed_actions=allowed, denied_actions=denied)


def _build_resource_scopes(raw: dict[str, Any], source: str) -> ResourceScopes:
    allowed = _require_pattern_list(
        raw, "allowed_patterns", f"{source}:resource_scopes"
    )
    denied = _require_pattern_list(
        raw, "denied_patterns", f"{source}:resource_scopes"
    )
    return ResourceScopes(allowed_patterns=allowed, denied_patterns=denied)


def _build_atx1_techniques(raw: dict[str, Any], source: str) -> tuple[str, ...]:
    if "atx1_techniques" not in raw:
        return ()
    items = raw["atx1_techniques"]
    if not isinstance(items, list):
        raise ProfileError(
            f"{source}:atx1_techniques must be a list, got {type(items).__name__}"
        )
    out: list[str] = []
    for index, item in enumerate(items):
        if not isinstance(item, str):
            raise ProfileError(
                f"{source}:atx1_techniques[{index}] must be a string, "
                f"got {type(item).__name__}"
            )
        if not _is_atx1_technique_id(item):
            raise ProfileError(
                f"{source}:atx1_techniques[{index}] must match the ATX-1 "
                f"technique ID format 'ATX-1.T-N-N', got {item!r}"
            )
        if item in out:
            raise ProfileError(
                f"{source}:atx1_techniques contains duplicate {item!r}"
            )
        out.append(item)
    return tuple(out)


def _build_agp_trace_id(raw: dict[str, Any], source: str) -> str | None:
    if "agp_trace_id" not in raw:
        return None
    value = raw["agp_trace_id"]
    if value is None:
        return None
    if not isinstance(value, str):
        raise ProfileError(
            f"{source}:agp_trace_id must be a string, got {type(value).__name__}"
        )
    if not value.strip():
        raise ProfileError(f"{source}:agp_trace_id must be non-empty if present")
    return value


def _build_delegation(raw: dict[str, Any], source: str) -> DelegationRules | None:
    if "delegation" not in raw:
        return None
    block = raw["delegation"]
    if block is None:
        return None
    if not isinstance(block, dict):
        raise ProfileError(
            f"{source}:delegation must be a mapping, got {type(block).__name__}"
        )

    max_depth = _require(block, "max_depth", f"{source}:delegation", int)
    if isinstance(max_depth, bool) or max_depth < 0:
        raise ProfileError(
            f"{source}:delegation.max_depth must be a non-negative integer, "
            f"got {max_depth!r}"
        )

    may = _require(block, "may_delegate_to", f"{source}:delegation", list)
    out: list[str] = []
    for index, item in enumerate(may):
        if not isinstance(item, str):
            raise ProfileError(
                f"{source}:delegation.may_delegate_to[{index}] must be a string, "
                f"got {type(item).__name__}"
            )
        if not item.startswith("role:") or not _is_snake_case(item[len("role:"):]):
            raise ProfileError(
                f"{source}:delegation.may_delegate_to[{index}] must match "
                f"'role:<snake_case>', got {item!r}"
            )
        if item in out:
            raise ProfileError(
                f"{source}:delegation.may_delegate_to contains duplicate {item!r}"
            )
        out.append(item)
    return DelegationRules(max_depth=int(max_depth), may_delegate_to=tuple(out))


# ── Validators ────────────────────────────────────────────────


def _require(
    raw: dict[str, Any], key: str, source: str, expected_type: type
) -> Any:
    if key not in raw:
        raise ProfileError(f"{source}: missing required key {key!r}")
    value = raw[key]
    if expected_type is int and isinstance(value, bool):
        raise ProfileError(
            f"{source}: {key!r} must be int, got bool"
        )
    if not isinstance(value, expected_type):
        raise ProfileError(
            f"{source}: {key!r} must be {expected_type.__name__}, "
            f"got {type(value).__name__}"
        )
    return value


def _require_str(raw: dict[str, Any], key: str, source: str) -> str:
    value = _require(raw, key, source, str)
    if not value.strip():
        raise ProfileError(f"{source}: {key!r} must be non-empty")
    return str(value)


def _require_action_list(
    raw: dict[str, Any], key: str, source: str
) -> tuple[str, ...]:
    items = _require(raw, key, source, list)
    if not items:
        raise ProfileError(f"{source}: {key!r} must be non-empty")
    out: list[str] = []
    for index, item in enumerate(items):
        if not isinstance(item, str):
            raise ProfileError(
                f"{source}: {key}[{index}] must be a string, "
                f"got {type(item).__name__}"
            )
        if not _is_snake_case(item):
            raise ProfileError(
                f"{source}: {key}[{index}] must be snake_case, got {item!r}"
            )
        if item in out:
            raise ProfileError(f"{source}: {key} contains duplicate {item!r}")
        out.append(item)
    return tuple(out)


def _require_pattern_list(
    raw: dict[str, Any], key: str, source: str
) -> tuple[str, ...]:
    items = _require(raw, key, source, list)
    if not items:
        raise ProfileError(f"{source}: {key!r} must be non-empty")
    out: list[str] = []
    for index, item in enumerate(items):
        if not isinstance(item, str):
            raise ProfileError(
                f"{source}: {key}[{index}] must be a string, "
                f"got {type(item).__name__}"
            )
        if not item.endswith("/*"):
            raise ProfileError(
                f"{source}: {key}[{index}] must end with '/*' "
                f"(prefix glob), got {item!r}"
            )
        if '"' in item or "\\" in item:
            raise ProfileError(
                f"{source}: {key}[{index}] must not contain backslash "
                f"or double quote, got {item!r}"
            )
        if item in out:
            raise ProfileError(f"{source}: {key} contains duplicate {item!r}")
        out.append(item)
    return tuple(out)


def _is_snake_case(value: str) -> bool:
    if not value:
        return False
    if not value[0].isalpha():
        return False
    return (
        all(c.islower() or c.isdigit() or c == "_" for c in value)
        and "__" not in value
    )


def _is_atx1_technique_id(value: str) -> bool:
    """ATX-1 technique IDs look like ``ATX-1.T-2-3`` or ``ATX-1.T-10-1``."""
    if not value.startswith("ATX-1.T-"):
        return False
    body = value[len("ATX-1.T-"):]
    parts = body.split("-")
    return len(parts) == 2 and all(p.isdigit() and p for p in parts)


# ── Cedar emission ────────────────────────────────────────────


def snake_to_pascal(snake: str) -> str:
    """Convert ``snake_case`` to ``PascalCase``.

    Matches AGT's ``_tool_to_cedar_action`` mapping (``file_read`` ->
    ``FileRead``).
    """
    return "".join(part[:1].upper() + part[1:] for part in snake.split("_") if part)


def _cedar_action_list(actions: tuple[str, ...]) -> str:
    return ",\n        ".join(f'Action::"{snake_to_pascal(a)}"' for a in actions)


def _cedar_pattern_disjunction(
    patterns: tuple[str, ...], context_field: str, indent: int
) -> str:
    sep = " ||\n" + " " * indent
    return sep.join(f'context.{context_field} like "{p}"' for p in patterns)


def compile_to_cedar(profile: GovernanceProfile) -> str:
    """Compile a profile to a Cedar policy string.

    Output is deterministic and ordered to match the source profile.
    AEGIS extensions (``atx1_techniques``, ``agp_trace_id``,
    ``delegation``) appear as informational header comments and, in
    the case of ``delegation``, as additional ``forbid`` clauses; basic
    rule semantics are unchanged.
    """
    base_header = (
        f"// AEGIS Governance Profile: {profile.metadata.profile_id} "
        f"v{profile.metadata.version}\n"
        f"// Schema: AEGIS profile {PROFILE_SCHEMA_VERSION}\n"
        f"// {profile.metadata.description.strip()}\n"
        "//\n"
        "// Generated by aegis_core.governance.profile.compile_to_cedar — "
        "DO NOT EDIT BY HAND.\n"
        "// Re-run the compiler against the source YAML to regenerate.\n"
    )
    extension_header = _cedar_extension_header(profile)
    header = base_header + extension_header

    permit_block = (
        "// Permit allowed actions when principal role and resource scope match.\n"
        "permit(\n"
        "    principal,\n"
        "    action in [\n"
        f"        {_cedar_action_list(profile.capabilities.allowed_actions)}\n"
        "    ],\n"
        "    resource\n"
        ")\n"
        "when {\n"
        f'    context.principal_role == "{profile.principal.role}" &&\n'
        "    (\n"
        f"        {_cedar_pattern_disjunction(profile.resource_scopes.allowed_patterns, 'resource_path', 8)}\n"  # noqa: E501
        "    )\n"
        "};\n"
    )

    forbid_actions_block = (
        "// Forbid denied actions outright (forbid overrides permit).\n"
        "forbid(\n"
        "    principal,\n"
        "    action in [\n"
        f"        {_cedar_action_list(profile.capabilities.denied_actions)}\n"
        "    ],\n"
        "    resource\n"
        ");\n"
    )

    forbid_scopes_block = (
        "// Forbid any action on denied resource paths.\n"
        "forbid(\n"
        "    principal,\n"
        "    action,\n"
        "    resource\n"
        ")\n"
        "when {\n"
        f"    {_cedar_pattern_disjunction(profile.resource_scopes.denied_patterns, 'resource_path', 4)}\n"  # noqa: E501
        "};\n"
    )

    blocks: list[str] = [header, permit_block, forbid_actions_block, forbid_scopes_block]

    delegation_block = _cedar_delegation_block(profile)
    if delegation_block is not None:
        blocks.append(delegation_block)

    return "\n".join(blocks)


def _cedar_extension_header(profile: GovernanceProfile) -> str:
    """Header lines for AEGIS extensions; empty string when no extensions set."""
    lines: list[str] = []
    if profile.atx1_techniques:
        joined = ", ".join(profile.atx1_techniques)
        lines.append(f"// ATX-1 techniques referenced: {joined}")
    if profile.agp_trace_id is not None:
        lines.append(f"// AGP-1 trace id: {profile.agp_trace_id}")
    if profile.delegation is not None:
        lines.append(
            f"// Delegation: max_depth={profile.delegation.max_depth}, "
            f"may_delegate_to={list(profile.delegation.may_delegate_to)}"
        )
    if not lines:
        return ""
    return "// --- AEGIS extensions ---\n" + "\n".join(lines) + "\n"


def _cedar_delegation_block(profile: GovernanceProfile) -> str | None:
    if profile.delegation is None:
        return None
    rule = profile.delegation
    return (
        "// AEGIS delegation rule: forbid when principal chain depth exceeds the cap.\n"
        "forbid(\n"
        "    principal,\n"
        "    action,\n"
        "    resource\n"
        ")\n"
        "when {\n"
        f"    context has \"delegation_depth\" && context.delegation_depth > {rule.max_depth}\n"
        "};\n"
    )


# ── Rego emission ─────────────────────────────────────────────


def _rego_set_literal(values: tuple[str, ...]) -> str:
    body = ",\n    ".join(f'"{v}"' for v in values)
    return "{\n    " + body + ",\n}"


def _rego_array_literal(values: tuple[str, ...]) -> str:
    body = ",\n    ".join(f'"{v}"' for v in values)
    return "[\n    " + body + ",\n]"


def _scope_prefix(pattern: str) -> str:
    return pattern[:-1]


def compile_to_rego(profile: GovernanceProfile) -> str:
    """Compile a profile to a Rego policy string.

    Emits Rego v1 (uses ``import rego.v1``). Deterministic — same
    profile produces byte-identical output on every run. AEGIS
    extensions appear as informational header comments and, in the
    case of ``delegation``, as an additional ``deny`` rule.
    """
    allowed_prefixes = tuple(
        _scope_prefix(p) for p in profile.resource_scopes.allowed_patterns
    )
    denied_prefixes = tuple(
        _scope_prefix(p) for p in profile.resource_scopes.denied_patterns
    )

    header = (
        f"# AEGIS Governance Profile: {profile.metadata.profile_id} "
        f"v{profile.metadata.version}\n"
        f"# Schema: AEGIS profile {PROFILE_SCHEMA_VERSION}\n"
        f"# {profile.metadata.description.strip()}\n"
        "#\n"
        "# Generated by aegis_core.governance.profile.compile_to_rego — "
        "DO NOT EDIT BY HAND.\n"
        "# Re-run the compiler against the source YAML to regenerate.\n"
    )
    extension_header = _rego_extension_header(profile)
    full_header = header + extension_header

    body = (
        "\n"
        "package agentos.aegis\n"
        "\n"
        "import rego.v1\n"
        "\n"
        "default allow := false\n"
        "\n"
        f"allowed_actions := {_rego_set_literal(profile.capabilities.allowed_actions)}\n"
        "\n"
        f"denied_actions := {_rego_set_literal(profile.capabilities.denied_actions)}\n"
        "\n"
        f"allowed_resource_patterns := {_rego_array_literal(allowed_prefixes)}\n"
        "\n"
        f"denied_resource_patterns := {_rego_array_literal(denied_prefixes)}\n"
        "\n"
        "allow if {\n"
        f'    input.principal_role == "{profile.principal.role}"\n'
        "    allowed_actions[input.tool_name]\n"
        "    in_allowed_scope\n"
        "    not in_denied_action\n"
        "    not in_denied_scope\n"
    )
    # Add delegation precondition to the main allow rule when present.
    if profile.delegation is not None:
        body += "    not exceeds_delegation_depth\n"
    body += (
        "}\n"
        "\n"
        "in_allowed_scope if {\n"
        "    some prefix in allowed_resource_patterns\n"
        "    startswith(input.resource_path, prefix)\n"
        "}\n"
        "\n"
        "in_denied_scope if {\n"
        "    some prefix in denied_resource_patterns\n"
        "    startswith(input.resource_path, prefix)\n"
        "}\n"
        "\n"
        "in_denied_action if {\n"
        "    denied_actions[input.tool_name]\n"
        "}\n"
    )
    delegation_block = _rego_delegation_block(profile)
    if delegation_block is not None:
        body += "\n" + delegation_block

    return full_header + body


def _rego_extension_header(profile: GovernanceProfile) -> str:
    lines: list[str] = []
    if profile.atx1_techniques:
        joined = ", ".join(profile.atx1_techniques)
        lines.append(f"# ATX-1 techniques referenced: {joined}")
    if profile.agp_trace_id is not None:
        lines.append(f"# AGP-1 trace id: {profile.agp_trace_id}")
    if profile.delegation is not None:
        lines.append(
            f"# Delegation: max_depth={profile.delegation.max_depth}, "
            f"may_delegate_to={list(profile.delegation.may_delegate_to)}"
        )
    if not lines:
        return ""
    return "# --- AEGIS extensions ---\n" + "\n".join(lines) + "\n"


def _rego_delegation_block(profile: GovernanceProfile) -> str | None:
    if profile.delegation is None:
        return None
    rule = profile.delegation
    return (
        "# AEGIS delegation rule: deny when principal chain depth exceeds the cap.\n"
        "exceeds_delegation_depth if {\n"
        f"    input.delegation_depth > {rule.max_depth}\n"
        "}\n"
    )
