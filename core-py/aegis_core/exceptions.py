"""Exceptions.

Defines the custom exception hierarchy used throughout the AEGIS runtime.
All runtime-specific failures should raise subclasses of :class:`AEGISError`.

Each exception carries structured metadata (error code, cause, help URL) to
support Stripe-style self-diagnosing error messages.  The :meth:`to_dict`
method serializes all fields for JSON API responses.
"""

from __future__ import annotations

from typing import Any

# Base URL for error documentation
_DOCS_BASE_URL = "https://aegis-docs.com/errors"


class AEGISError(Exception):
    """Base exception for all AEGIS errors.

    This is the parent class for all AEGIS-specific exceptions. All AEGIS
    failures should raise a subclass of this exception.

    Parameters
    ----------
    message : str
        Human-readable error message explaining what went wrong.
    error_code : str, optional
        Machine-readable error code for programmatic error handling.
    cause : str, optional
        The specific policy ID, capability, rule, or field that triggered
        the error.
    help_url : str, optional
        Link to documentation for this error.  Auto-generated from
        *error_code* when not provided.

    Attributes
    ----------
    error_code : str
        Machine-readable code uniquely identifying this error type.
    cause : str or None
        The specific entity that triggered the error.
    help_url : str or None
        Documentation URL for this error.
    """

    error_code: str = "AEGIS_ERROR"

    def __init__(
        self,
        message: str,
        error_code: str | None = None,
        cause: str | None = None,
        help_url: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if error_code is not None:
            self.error_code = error_code
        self.cause = cause
        self.help_url = help_url if help_url is not None else self._build_help_url()

    def _build_help_url(self) -> str:
        """Generate a documentation URL from the error code."""
        code = self.error_code.lower().replace("-", "_")
        return f"{_DOCS_BASE_URL}/{code}"

    def to_dict(self) -> dict[str, Any]:
        """Return a structured dictionary suitable for JSON API responses.

        Returns
        -------
        dict
            Dictionary with keys: ``error_code``, ``message``, ``cause``,
            ``help_url``, and ``type`` (the exception class name).
        """
        return {
            "type": type(self).__name__,
            "error_code": self.error_code,
            "message": self.message,
            "cause": self.cause,
            "help_url": self.help_url,
        }

    def __str__(self) -> str:
        """Format as ``[ERROR_CODE] message``."""
        return f"[{self.error_code}] {self.message}"


class AEGISValidationError(AEGISError):
    """Raised when an AGP request fails schema or semantic validation.

    A validation error occurs when:
    - Request structure is malformed or missing required fields
    - Field values violate semantic constraints (e.g., empty agent_id)
    - Request parameters are invalid for the specified action type
    - Requested capability does not exist in the registry

    Examples
    --------
    >>> # Missing required field
    >>> raise AEGISValidationError("agent_id must not be empty")

    >>> # Invalid action type for target
    >>> raise AEGISValidationError(
    ...     "FILE_WRITE not supported for URL targets",
    ...     error_code="AEGIS-VAL-010"
    ... )
    """

    error_code: str = "VALIDATION_ERROR"


class AEGISCapabilityError(AEGISError):
    """Raised when an agent lacks the capability required for an action.

    A capability error indicates:
    - The requested capability does not exist in the registry
    - The agent's authorization does not include the required capability
    - The action targets a resource class the agent cannot access

    This is thrown by the Decision Engine during capability authorization
    evaluation and often results in a DENIED governance decision.

    Examples
    --------
    >>> # Capability not registered
    >>> raise AEGISCapabilityError(
    ...     "Capability 'database.admin' not found in registry"
    ... )

    >>> # Agent not authorized
    >>> raise AEGISCapabilityError(
    ...     "Agent read-only-agent lacks capability 'database.write'",
    ...     error_code="AEGIS-CAP-002"
    ... )
    """

    error_code: str = "CAPABILITY_ERROR"


class AEGISPolicyError(AEGISError):
    """Raised when policy evaluation encounters an unexpected error.

    A policy error indicates a problem during governance policy evaluation:
    - Policy syntax is invalid or unparseable
    - Policy evaluation logic encounters a runtime error
    - Required policy context is missing
    - Policy database is unavailable or corrupted

    This typically results in a ESCALATE decision pending investigation.

    Examples
    --------
    >>> # Policy syntax error
    >>> raise AEGISPolicyError(
    ...     "Policy 'production-db' has invalid time constraint syntax"
    ... )

    >>> # Missing policy data
    >>> raise AEGISPolicyError(
    ...     "Could not load policy: database connection failed",
    ...     error_code="AEGIS-POL-003"
    ... )
    """

    error_code: str = "POLICY_ERROR"


class AEGISAuditError(AEGISError):
    """Raised when the audit system is unable to record a decision.

    An audit error indicates that a governance decision was made but could
    not be recorded in the immutable audit trail. This is a critical error
    as it violates the AEGIS principle of complete auditability.

    Common causes:
    - Audit database is offline or full
    - Audit storage permissions denied
    - Audit log corruption detected
    - Audit replication to federation failed

    Examples
    --------
    >>> # Database unavailable
    >>> raise AEGISAuditError(
    ...     "Could not write audit entry: SQLite database locked"
    ... )

    >>> # Storage quota exceeded
    >>> raise AEGISAuditError(
    ...     "Audit storage quota exceeded",
    ...     error_code="AEGIS-AUD-002"
    ... )
    """

    error_code: str = "AUDIT_ERROR"
