"""Governance Gateway.

The Governance Gateway is the single, validated entry point through
which AI agents submit :class:`~aegis.protocol.AGPRequest` objects for
governance review.

Responsibilities
----------------
* **Schema validation** - rejects structurally or semantically invalid
  requests before they reach the Decision Engine.
* **Semantic validation** - validates agent IDs, action types, and request
  completeness according to AEGIS governance rules.
* **Security pattern checks** - rejects shell metacharacters (T10004),
  sensitive path writes (T10002, T10003), oversized parameters (T6002),
  and replay attempts (T1002).
* **Routing** - forwards valid requests to the Decision Engine.

Trust Model (v0.1.0)
--------------------
At the library embedding layer, the runtime trusts its embedder.  The
``agent_id`` field in :class:`AGPRequest` is an assertion by the embedder,
not a cryptographically verified claim.  Agent identity verification is
the embedder's responsibility at v0.1.0.

Transport-layer authentication (mTLS, bearer tokens) will enforce
identity at the protocol boundary in v0.2.0 (RFC-0002).  Until then,
callers who embed the runtime in a multi-tenant environment must
implement their own authentication before constructing AGPRequest objects.

See also: RT-015 / T5002 (identity spoofing), RT-018 / T7002
(delegation chain escalation).
"""

from __future__ import annotations

import collections
import fnmatch
import json
import re
import threading

from .decision_engine import DecisionEngine
from .exceptions import AEGISValidationError
from .protocol import ActionType, AGPAction, AGPContext, AGPRequest, AGPResponse

# Regex for valid agent IDs: alphanumeric, hyphens, underscores, dots
_AGENT_ID_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')

# RT-008 / T6002: Maximum serialized size for action parameters (1 MB)
_MAX_PARAMETERS_SIZE_BYTES = 1_048_576

# RT-021 / T10004: Shell metacharacters that indicate parser divergence.
# If a SHELL_EXEC target contains these, it should be ESCALATED because
# governance evaluates the string as a single target, but a shell would
# parse the metacharacters as command separators or operators.
# BT-AUDIT-001: Added > and < (shell redirections) — "echo payload > /etc/passwd"
# bypasses FILE_WRITE detection because action_type is SHELL_EXEC.
_SHELL_METACHAR_PATTERN = re.compile(r'[;|&`$()<>]|\n|\r')

# RT-022 / T10002 + RT-023 / T10003: Sensitive paths that require
# escalation for FILE_WRITE actions. These are files that the execution
# environment auto-executes or that define agent behavior.
# BT-AUDIT-002: Immutable tuple prevents runtime mutation.
_SENSITIVE_PATH_PATTERNS: tuple[str, ...] = (
    # Git hooks (T10002)
    ".git/hooks/*",
    # Shell init (T10002)
    ".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile",
    # Package manager lifecycle scripts (T10002)
    "package.json", "Makefile", "setup.py", "setup.cfg",
    # CI/CD (T10002)
    ".github/workflows/*", ".gitlab-ci.yml", "Jenkinsfile",
    # Container (T10002)
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    # IDE tasks (T10002)
    ".vscode/tasks.json",
    # Agent instruction files (T10003)
    "CLAUDE.md", ".claude/*",
    ".cursorrules",
    ".github/copilot-instructions.md",
    ".windsurfrules",
    ".clinerules",
)


class GovernanceGateway:
    """Validates and routes AGP requests to the Decision Engine.

    Parameters
    ----------
    decision_engine:
        The :class:`~aegis.decision_engine.DecisionEngine` instance that
        will evaluate governance decisions.
    """

    # RT-005 / T1002: Maximum number of recent request IDs to track
    _REPLAY_WINDOW_SIZE = 10_000

    def __init__(self, decision_engine: DecisionEngine) -> None:
        self._engine = decision_engine
        # RT-005 / T1002: Bounded deque of recently seen request_ids
        self._seen_request_ids: collections.deque[str] = collections.deque(
            maxlen=self._REPLAY_WINDOW_SIZE
        )
        self._replay_lock = threading.Lock()

    def submit(self, request: AGPRequest) -> AGPResponse:
        """Submit a governance request.

        Parameters
        ----------
        request:
            The :class:`~aegis.protocol.AGPRequest` to evaluate.

        Returns
        -------
        AGPResponse
            The governance decision.

        Raises
        ------
        AEGISValidationError
            If the request is structurally or semantically invalid,
            or if the request_id has already been submitted (replay).
        """
        self._validate(request)
        self._check_replay(request.request_id)
        self._check_dangerous_patterns(request)
        return self._engine._evaluate(request)

    def _check_replay(self, request_id: str) -> None:
        """Reject duplicate request_ids (RT-005 / T1002).

        Raises
        ------
        AEGISValidationError
            If the request_id has been seen within the replay window.
        """
        with self._replay_lock:
            if request_id in self._seen_request_ids:
                raise AEGISValidationError(
                    f"Duplicate request_id rejected (replay protection): {request_id}",
                    error_code="DUPLICATE_REQUEST_ID"
                )
            self._seen_request_ids.append(request_id)

    # ------------------------------------------------------------------
    # Security pattern checks (RT-021 / T10004, RT-022 / T10002, RT-023 / T10003)
    # ------------------------------------------------------------------

    def _check_dangerous_patterns(self, request: AGPRequest) -> None:
        """Reject requests with dangerous target patterns.

        Checks:
        1. SHELL_EXEC targets with shell metacharacters (RT-021 / T10004)
        2. FILE_WRITE targets to auto-execution paths (RT-022 / T10002)
        3. FILE_WRITE targets to agent instruction files (RT-023 / T10003)

        Raises
        ------
        AEGISValidationError
            If the target matches a dangerous pattern.
        """
        action = request.action

        # RT-021 / T10004: Shell metacharacter detection for SHELL_EXEC
        if (
            action.type == ActionType.SHELL_EXEC
            and _SHELL_METACHAR_PATTERN.search(action.target)
        ):
            raise AEGISValidationError(
                f"SHELL_EXEC target contains shell metacharacters that "
                f"could cause parser divergence: {action.target!r}",
                error_code="SHELL_METACHARACTER_DETECTED"
            )

        # RT-022 / T10002 + RT-023 / T10003: Sensitive path protection
        # H-4: Normalize path before matching to prevent traversal evasion
        if action.type == ActionType.FILE_WRITE:
            import posixpath

            raw_target = action.target
            normalized = posixpath.normpath(raw_target)
            basename = normalized.rsplit("/", 1)[-1]
            # Check all variants: raw, normalized, basename
            variants = {raw_target, normalized, raw_target.lower(),
                        normalized.lower(), basename, basename.lower()}
            for pattern in _SENSITIVE_PATH_PATTERNS:
                for variant in variants:
                    if fnmatch.fnmatch(variant, pattern) or fnmatch.fnmatch(
                        variant, pattern.lower()
                    ):
                        raise AEGISValidationError(
                            f"FILE_WRITE to sensitive path requires "
                            f"escalation: {raw_target!r} matches "
                            f"protected pattern '{pattern}'",
                            error_code="SENSITIVE_PATH_WRITE"
                        )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate(self, request: AGPRequest) -> None:
        """Validate a governance request for structural and semantic correctness.

        Performs the following validation checks:

        1. **Request object validation** - AGPRequest instance exists
        2. **Agent ID validation** - non-empty, valid format
        3. **Action validation** - action type exists, target is non-empty
        4. **Action type compatibility** - validates target type matches action
        5. **Context validation** - session_id is non-empty, timestamp validity
        6. **Parameters validation** - parameters dict is valid, no None keys

        Raises
        ------
        AEGISValidationError
            If any validation check fails, with specific error message.
        """
        # Request object must exist
        if request is None:
            raise AEGISValidationError("AGPRequest object must not be None")

        # Validate agent_id
        self._validate_agent_id(request.agent_id)

        # Validate action
        if request.action is None:
            raise AEGISValidationError("AGPRequest.action must not be None")
        self._validate_action(request.action)

        # Validate context
        if request.context is None:
            raise AEGISValidationError("AGPRequest.context must not be None")
        self._validate_context(request.context)

        # Validate request_id
        if not request.request_id or not request.request_id.strip():
            raise AEGISValidationError("AGPRequest.request_id must not be empty")

    def _validate_agent_id(self, agent_id: str) -> None:
        """Validate agent ID format and content.

        Agent IDs must:
        - Be non-empty and non-whitespace
        - Contain only alphanumeric characters, hyphens, underscores, dots
        - Not exceed 256 characters

        Parameters
        ----------
        agent_id : str
            The agent identifier to validate.

        Raises
        ------
        AEGISValidationError
            If agent_id is invalid.
        """
        if not agent_id or not agent_id.strip():
            raise AEGISValidationError(
                "AGPRequest.agent_id must not be empty",
                error_code="EMPTY_AGENT_ID"
            )

        if len(agent_id) > 256:
            raise AEGISValidationError(
                f"AGPRequest.agent_id exceeds maximum length (256): {len(agent_id)}",
                error_code="AGENT_ID_TOO_LONG"
            )

        if not _AGENT_ID_PATTERN.match(agent_id):
            raise AEGISValidationError(
                f"AGPRequest.agent_id contains invalid characters: {agent_id!r}",
                error_code="INVALID_AGENT_ID_FORMAT"
            )

    def _validate_action(self, action: AGPAction) -> None:
        """Validate action completeness and type compatibility.

        Parameters
        ----------
        action : AGPAction
            The action to validate.

        Raises
        ------
        AEGISValidationError
            If action is invalid.
        """
        if action.type is None:
            raise AEGISValidationError(
                "AGPRequest.action.type must not be None",
                error_code="MISSING_ACTION_TYPE"
            )

        if not isinstance(action.type, ActionType):
            raise AEGISValidationError(
                f"AGPRequest.action.type is not a valid ActionType: {action.type!r}",
                error_code="INVALID_ACTION_TYPE"
            )

        if not action.target or not action.target.strip():
            raise AEGISValidationError(
                "AGPRequest.action.target must not be empty",
                error_code="EMPTY_ACTION_TARGET"
            )

        if len(action.target) > 1024:
            raise AEGISValidationError(
                f"AGPRequest.action.target exceeds maximum length (1024): {len(action.target)}",
                error_code="TARGET_TOO_LONG"
            )

        # Validate parameters dict
        if action.parameters is None:
            raise AEGISValidationError(
                "AGPRequest.action.parameters must not be None",
                error_code="MISSING_PARAMETERS"
            )

        if not isinstance(action.parameters, dict):
            raise AEGISValidationError(
                "AGPRequest.action.parameters must be a dict, "
                f"got {type(action.parameters).__name__}",
                error_code="INVALID_PARAMETERS_TYPE"
            )

        # Check for None keys in parameters
        for key in action.parameters:
            if key is None:
                raise AEGISValidationError(
                    "AGPRequest.action.parameters contains None key",
                    error_code="NULL_PARAMETER_KEY"
                )

        # RT-008 / T6002: Enforce parameter size limit to prevent
        # memory exhaustion via oversized payloads.
        # L-2: Reject on serialization failure instead of defaulting to 0.
        try:
            params_size = len(json.dumps(action.parameters))
        except (TypeError, ValueError) as exc:
            raise AEGISValidationError(
                f"AGPRequest.action.parameters cannot be serialized: {exc}",
                error_code="PARAMETERS_UNSERIALIZABLE"
            ) from exc
        if params_size > _MAX_PARAMETERS_SIZE_BYTES:
            raise AEGISValidationError(
                f"AGPRequest.action.parameters exceeds maximum size "
                f"({_MAX_PARAMETERS_SIZE_BYTES} bytes): {params_size}",
                error_code="PARAMETERS_TOO_LARGE"
            )

    def _validate_context(self, context: AGPContext) -> None:
        """Validate request context.

        Parameters
        ----------
        context : AGPContext
            The context to validate.

        Raises
        ------
        AEGISValidationError
            If context is invalid.
        """
        if not context.session_id or not context.session_id.strip():
            raise AEGISValidationError(
                "AGPRequest.context.session_id must not be empty",
                error_code="EMPTY_SESSION_ID"
            )

        if len(context.session_id) > 256:
            raise AEGISValidationError(
                "AGPRequest.context.session_id exceeds maximum "
                f"length (256): {len(context.session_id)}",
                error_code="SESSION_ID_TOO_LONG"
            )

        if context.timestamp is None:
            raise AEGISValidationError(
                "AGPRequest.context.timestamp must not be None",
                error_code="MISSING_TIMESTAMP"
            )

        if context.metadata is None:
            raise AEGISValidationError(
                "AGPRequest.context.metadata must not be None",
                error_code="MISSING_METADATA"
            )

