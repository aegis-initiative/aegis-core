"""Error Catalog.

Canonical, machine-readable error codes for the AEGIS governance runtime.
Every ``raise`` site references a constant from this module to ensure
consistency and enable programmatic error handling.

Code format: ``AEGIS-{CATEGORY}-{NNN}``

Categories
----------
VAL  Validation errors (gateway and engine input validation)
CAP  Capability errors (registry, grants, freeze/unseal)
POL  Policy errors (engine, freeze/unseal, evaluation)
AUD  Audit errors (persistence, batch operations)
"""

# ---- Validation errors (gateway) ----------------------------------------

VAL_NULL_REQUEST = "AEGIS-VAL-001"
"""AGPRequest object is None."""

VAL_EMPTY_AGENT_ID = "AEGIS-VAL-002"
"""agent_id is empty or whitespace-only."""

VAL_AGENT_ID_TOO_LONG = "AEGIS-VAL-003"
"""agent_id exceeds 256 characters."""

VAL_INVALID_AGENT_ID_FORMAT = "AEGIS-VAL-004"
"""agent_id contains characters outside [a-zA-Z0-9._-]."""

VAL_NULL_ACTION = "AEGIS-VAL-005"
"""AGPRequest.action is None."""

VAL_MISSING_ACTION_TYPE = "AEGIS-VAL-006"
"""AGPRequest.action.type is None."""

VAL_INVALID_ACTION_TYPE = "AEGIS-VAL-007"
"""AGPRequest.action.type is not a valid ActionType enum member."""

VAL_EMPTY_ACTION_TARGET = "AEGIS-VAL-008"
"""AGPRequest.action.target is empty or whitespace-only."""

VAL_TARGET_TOO_LONG = "AEGIS-VAL-009"
"""AGPRequest.action.target exceeds 1024 characters."""

VAL_NULL_PARAMETERS = "AEGIS-VAL-010"
"""AGPRequest.action.parameters is None."""

VAL_INVALID_PARAMETERS_TYPE = "AEGIS-VAL-011"
"""AGPRequest.action.parameters is not a dict."""

VAL_NULL_PARAMETER_KEY = "AEGIS-VAL-012"
"""AGPRequest.action.parameters contains a None key."""

VAL_PARAMETERS_UNSERIALIZABLE = "AEGIS-VAL-013"
"""AGPRequest.action.parameters cannot be JSON-serialized."""

VAL_PARAMETERS_TOO_LARGE = "AEGIS-VAL-014"
"""Serialized parameters exceed 1 MB size limit (T6002)."""

VAL_NULL_CONTEXT = "AEGIS-VAL-015"
"""AGPRequest.context is None."""

VAL_EMPTY_SESSION_ID = "AEGIS-VAL-016"
"""AGPRequest.context.session_id is empty or whitespace-only."""

VAL_SESSION_ID_TOO_LONG = "AEGIS-VAL-017"
"""AGPRequest.context.session_id exceeds 256 characters."""

VAL_MISSING_TIMESTAMP = "AEGIS-VAL-018"
"""AGPRequest.context.timestamp is None."""

VAL_MISSING_METADATA = "AEGIS-VAL-019"
"""AGPRequest.context.metadata is None."""

VAL_EMPTY_REQUEST_ID = "AEGIS-VAL-020"
"""AGPRequest.request_id is empty or whitespace-only."""

VAL_DUPLICATE_REQUEST_ID = "AEGIS-VAL-021"
"""request_id already submitted within replay window (T1002)."""

VAL_SHELL_METACHARACTER = "AEGIS-VAL-022"
"""SHELL_EXEC target contains shell metacharacters (T10004)."""

VAL_SENSITIVE_PATH_WRITE = "AEGIS-VAL-023"
"""FILE_WRITE targets a sensitive/auto-execution path (T10002/T10003)."""

# ---- Validation errors (engine defense-in-depth) -------------------------

VAL_ENGINE_NULL_REQUEST = "AEGIS-VAL-050"
"""Engine received a None request (defense-in-depth)."""

VAL_ENGINE_MISSING_AGENT_ID = "AEGIS-VAL-051"
"""Engine received a request without agent_id."""

VAL_ENGINE_MISSING_REQUEST_ID = "AEGIS-VAL-052"
"""Engine received a request without request_id."""

VAL_ENGINE_NULL_ACTION = "AEGIS-VAL-053"
"""Engine received a request with None action."""

VAL_ENGINE_INVALID_ACTION_TYPE = "AEGIS-VAL-054"
"""Engine received an invalid action type."""

VAL_ENGINE_EMPTY_TARGET = "AEGIS-VAL-055"
"""Engine received a request with empty action target."""

VAL_ENGINE_NULL_CONTEXT = "AEGIS-VAL-056"
"""Engine received a request with None context."""

VAL_ENGINE_EMPTY_SESSION_ID = "AEGIS-VAL-057"
"""Engine received a request with empty session_id."""

# ---- Capability errors ---------------------------------------------------

CAP_INVALID_SEAL_TOKEN = "AEGIS-CAP-001"
"""Seal token does not match — cannot unseal the capability registry."""

CAP_REGISTRY_FROZEN = "AEGIS-CAP-002"
"""Mutation attempted on a frozen capability registry."""

CAP_REGISTRY_CAPACITY = "AEGIS-CAP-003"
"""Capability registry has reached its maximum capacity."""

CAP_UNKNOWN_CAPABILITY = "AEGIS-CAP-004"
"""Referenced capability ID is not registered."""

# ---- Policy errors -------------------------------------------------------

POL_INVALID_SEAL_TOKEN = "AEGIS-POL-001"
"""Seal token does not match — cannot unseal the policy engine."""

POL_ENGINE_FROZEN = "AEGIS-POL-002"
"""Mutation attempted on a frozen policy engine."""

POL_EMPTY_POLICY_ID = "AEGIS-POL-003"
"""Policy.id is empty or whitespace-only."""

POL_EMPTY_POLICY_NAME = "AEGIS-POL-004"
"""Policy.name is empty or whitespace-only."""

POL_INVALID_EFFECT = "AEGIS-POL-005"
"""Policy.effect is not a valid PolicyEffect value."""

POL_INVALID_CONDITIONS_TYPE = "AEGIS-POL-006"
"""Policy.conditions is not a list."""

POL_NONCALLABLE_CONDITION = "AEGIS-POL-007"
"""A policy condition's evaluate attribute is not callable."""

POL_EMPTY_CONDITION_DESC = "AEGIS-POL-008"
"""A policy condition's description is empty or whitespace-only."""

POL_CONDITION_ERROR = "AEGIS-POL-009"
"""A policy condition raised an unexpected exception during evaluation."""

# ---- Audit errors --------------------------------------------------------

AUD_PERSIST_ERROR = "AEGIS-AUD-001"
"""Failed to persist an audit record to the database."""

AUD_BATCH_PERSIST_ERROR = "AEGIS-AUD-002"
"""Failed to persist a batch of audit records to the database."""
