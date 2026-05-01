"""AEGIS Governance subpackage — declarative authorization profiles.

Compiles AEGIS Governance Profiles (declarative YAML descriptions of
*what an agent class is permitted to do*) into Cedar and Rego policies
suitable for downstream policy engines.

Profiles are an authoring layer above Cedar / Rego: they describe the
high-level governance concepts (role, capabilities, resource scopes)
that compliance and governance stakeholders work in, and the compiler
fans them out to both AGT external policy backends from a single
reviewed file.

A standalone subset of this compiler is also published as a community
example contribution to Microsoft's Agent Governance Toolkit (AGT) at
``examples/aegis-governance-profile/`` in `microsoft/agent-governance-toolkit`.
The two compilers produce byte-identical output for the basic profile
schema; this version adds AEGIS-only extensions (ATX-1 technique
references, AGP-1 trace identifiers, delegation rules).

See :mod:`aegis_core.governance.profile` for the full module docstring,
schema reference, and extension semantics.
"""

from __future__ import annotations

from .profile import (
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
