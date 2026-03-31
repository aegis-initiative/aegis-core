# schemas — Shared JSON Schemas

Language-agnostic JSON Schema definitions shared between the Python and Rust implementations.

## Status

**Not yet populated.** Schema definitions will be added as the AGP-1 protocol interfaces stabilize
in the Python reference implementation.

## Purpose

These schemas define the canonical wire format for:

- `ACTION_PROPOSE` messages (input to the governance gateway)
- `DECISION_RESPONSE` messages (output from the governance gateway)
- Capability declarations and permission grants
- Policy rule definitions
- Risk assessment results
- Audit records

Both `core-py` and `core-rs` must validate against these schemas, ensuring protocol compatibility
regardless of implementation language.

## Relationship to aegis (specs repo)

The master schema definitions live in
[aegis-initiative/aegis](https://github.com/aegis-initiative/aegis). Schemas in this directory are
either copied from or symlinked to the specs repo to keep implementations in sync.
