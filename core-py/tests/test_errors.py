"""Tests for the AEGIS error system.

Validates the enhanced exception hierarchy: structured fields, error code
formatting, help URL auto-generation, to_dict() serialization, and
__str__() output format.
"""

import pytest

from aegis_core import errors
from aegis_core.exceptions import (
    AEGISAuditError,
    AEGISCapabilityError,
    AEGISError,
    AEGISPolicyError,
    AEGISValidationError,
)


# ---- AEGISError base class -----------------------------------------------


class TestAEGISErrorBase:
    """Tests for the AEGISError base exception."""

    def test_basic_construction(self):
        err = AEGISError("something went wrong")
        assert err.message == "something went wrong"
        assert err.error_code == "AEGIS_ERROR"  # class default
        assert err.cause is None
        assert err.help_url is not None

    def test_custom_error_code(self):
        err = AEGISError("bad", error_code="AEGIS-VAL-001")
        assert err.error_code == "AEGIS-VAL-001"

    def test_cause_field(self):
        err = AEGISError("bad", cause="request.agent_id")
        assert err.cause == "request.agent_id"

    def test_explicit_help_url(self):
        url = "https://example.com/help"
        err = AEGISError("bad", help_url=url)
        assert err.help_url == url

    def test_auto_help_url_from_error_code(self):
        err = AEGISError("bad", error_code="AEGIS-VAL-001")
        assert err.help_url == "https://aegis-docs.com/errors/aegis_val_001"

    def test_auto_help_url_default_code(self):
        err = AEGISError("bad")
        assert err.help_url == "https://aegis-docs.com/errors/aegis_error"

    def test_str_format(self):
        err = AEGISError("something broke", error_code="AEGIS-VAL-001")
        assert str(err) == "[AEGIS-VAL-001] something broke"

    def test_str_format_default_code(self):
        err = AEGISError("something broke")
        assert str(err) == "[AEGIS_ERROR] something broke"

    def test_to_dict_structure(self):
        err = AEGISError(
            "bad input",
            error_code="AEGIS-VAL-002",
            cause="request.agent_id",
        )
        d = err.to_dict()
        assert d["type"] == "AEGISError"
        assert d["error_code"] == "AEGIS-VAL-002"
        assert d["message"] == "bad input"
        assert d["cause"] == "request.agent_id"
        assert d["help_url"] == "https://aegis-docs.com/errors/aegis_val_002"

    def test_to_dict_none_cause(self):
        err = AEGISError("bad")
        d = err.to_dict()
        assert d["cause"] is None

    def test_is_exception(self):
        err = AEGISError("test")
        assert isinstance(err, Exception)

    def test_args_tuple(self):
        """super().__init__(message) puts message in args."""
        err = AEGISError("hello")
        assert err.args == ("hello",)

    def test_backward_compat_positional(self):
        """error_code as keyword still works."""
        err = AEGISError("msg", error_code="CODE")
        assert err.error_code == "CODE"


# ---- Subclass inheritance ------------------------------------------------


class TestSubclassInheritance:
    """Every subclass should inherit the enhanced behavior."""

    @pytest.mark.parametrize(
        "cls,default_code",
        [
            (AEGISValidationError, "VALIDATION_ERROR"),
            (AEGISCapabilityError, "CAPABILITY_ERROR"),
            (AEGISPolicyError, "POLICY_ERROR"),
            (AEGISAuditError, "AUDIT_ERROR"),
        ],
    )
    def test_default_error_code(self, cls, default_code):
        err = cls("test message")
        assert err.error_code == default_code

    @pytest.mark.parametrize(
        "cls",
        [
            AEGISValidationError,
            AEGISCapabilityError,
            AEGISPolicyError,
            AEGISAuditError,
        ],
    )
    def test_custom_error_code_overrides_default(self, cls):
        err = cls("msg", error_code="AEGIS-CUSTOM-999")
        assert err.error_code == "AEGIS-CUSTOM-999"

    @pytest.mark.parametrize(
        "cls",
        [
            AEGISValidationError,
            AEGISCapabilityError,
            AEGISPolicyError,
            AEGISAuditError,
        ],
    )
    def test_cause_and_help_url(self, cls):
        err = cls("msg", error_code="AEGIS-X-001", cause="field.name")
        assert err.cause == "field.name"
        assert "aegis_x_001" in err.help_url

    @pytest.mark.parametrize(
        "cls",
        [
            AEGISValidationError,
            AEGISCapabilityError,
            AEGISPolicyError,
            AEGISAuditError,
        ],
    )
    def test_to_dict_type_name(self, cls):
        err = cls("msg")
        d = err.to_dict()
        assert d["type"] == cls.__name__

    @pytest.mark.parametrize(
        "cls",
        [
            AEGISValidationError,
            AEGISCapabilityError,
            AEGISPolicyError,
            AEGISAuditError,
        ],
    )
    def test_str_format(self, cls):
        err = cls("details", error_code="AEGIS-T-001")
        assert str(err) == "[AEGIS-T-001] details"

    @pytest.mark.parametrize(
        "cls",
        [
            AEGISValidationError,
            AEGISCapabilityError,
            AEGISPolicyError,
            AEGISAuditError,
        ],
    )
    def test_isinstance_aegis_error(self, cls):
        err = cls("msg")
        assert isinstance(err, AEGISError)
        assert isinstance(err, Exception)


# ---- Error catalog constants ---------------------------------------------


class TestErrorCatalog:
    """Verify catalog constants follow the naming convention."""

    def test_val_codes_start_with_aegis_val(self):
        val_codes = [
            v for k, v in vars(errors).items()
            if k.startswith("VAL_") and isinstance(v, str)
        ]
        assert len(val_codes) > 0
        for code in val_codes:
            assert code.startswith("AEGIS-VAL-"), f"{code} should start with AEGIS-VAL-"

    def test_cap_codes_start_with_aegis_cap(self):
        cap_codes = [
            v for k, v in vars(errors).items()
            if k.startswith("CAP_") and isinstance(v, str)
        ]
        assert len(cap_codes) > 0
        for code in cap_codes:
            assert code.startswith("AEGIS-CAP-"), f"{code} should start with AEGIS-CAP-"

    def test_pol_codes_start_with_aegis_pol(self):
        pol_codes = [
            v for k, v in vars(errors).items()
            if k.startswith("POL_") and isinstance(v, str)
        ]
        assert len(pol_codes) > 0
        for code in pol_codes:
            assert code.startswith("AEGIS-POL-"), f"{code} should start with AEGIS-POL-"

    def test_aud_codes_start_with_aegis_aud(self):
        aud_codes = [
            v for k, v in vars(errors).items()
            if k.startswith("AUD_") and isinstance(v, str)
        ]
        assert len(aud_codes) > 0
        for code in aud_codes:
            assert code.startswith("AEGIS-AUD-"), f"{code} should start with AEGIS-AUD-"

    def test_no_duplicate_codes(self):
        all_codes = [
            v for k, v in vars(errors).items()
            if isinstance(v, str) and v.startswith("AEGIS-")
        ]
        assert len(all_codes) == len(set(all_codes)), "Duplicate error codes found"

    def test_specific_code_values(self):
        assert errors.VAL_NULL_REQUEST == "AEGIS-VAL-001"
        assert errors.VAL_EMPTY_AGENT_ID == "AEGIS-VAL-002"
        assert errors.CAP_INVALID_SEAL_TOKEN == "AEGIS-CAP-001"
        assert errors.POL_INVALID_SEAL_TOKEN == "AEGIS-POL-001"
        assert errors.AUD_PERSIST_ERROR == "AEGIS-AUD-001"


# ---- Integration: errors used in raise sites -----------------------------


class TestErrorIntegration:
    """Verify that catalog codes are usable in exception constructors."""

    def test_validation_error_with_catalog_code(self):
        err = AEGISValidationError(
            "agent_id is required but was empty or whitespace-only",
            error_code=errors.VAL_EMPTY_AGENT_ID,
            cause="request.agent_id",
        )
        assert err.error_code == "AEGIS-VAL-002"
        assert err.cause == "request.agent_id"
        assert "aegis_val_002" in err.help_url
        assert str(err) == "[AEGIS-VAL-002] agent_id is required but was empty or whitespace-only"

    def test_capability_error_with_catalog_code(self):
        err = AEGISCapabilityError(
            "Cannot grant unknown capability 'database.admin'",
            error_code=errors.CAP_UNKNOWN_CAPABILITY,
            cause="database.admin",
        )
        d = err.to_dict()
        assert d["error_code"] == "AEGIS-CAP-004"
        assert d["cause"] == "database.admin"
        assert d["type"] == "AEGISCapabilityError"

    def test_policy_error_with_catalog_code(self):
        err = AEGISPolicyError(
            "Policy 'prod-deny' condition raised an error: division by zero",
            error_code=errors.POL_CONDITION_ERROR,
            cause="prod-deny",
        )
        assert err.error_code == "AEGIS-POL-009"
        assert err.cause == "prod-deny"

    def test_audit_error_with_catalog_code(self):
        err = AEGISAuditError(
            "Failed to persist audit record: database is locked",
            error_code=errors.AUD_PERSIST_ERROR,
            cause="audit_records",
        )
        assert err.error_code == "AEGIS-AUD-001"
        assert err.cause == "audit_records"


# ---- to_dict JSON serialization ------------------------------------------


class TestToDict:
    """Verify to_dict() output is JSON-compatible."""

    def test_json_serializable(self):
        import json

        err = AEGISValidationError(
            "bad input",
            error_code=errors.VAL_EMPTY_AGENT_ID,
            cause="request.agent_id",
        )
        d = err.to_dict()
        # Should not raise
        serialized = json.dumps(d)
        assert isinstance(serialized, str)

    def test_all_keys_present(self):
        err = AEGISError("msg")
        d = err.to_dict()
        expected_keys = {"type", "error_code", "message", "cause", "help_url"}
        assert set(d.keys()) == expected_keys


# ---- Module import -------------------------------------------------------


class TestModuleImport:
    """Verify the errors module is importable from aegis_core."""

    def test_import_errors_module(self):
        from aegis_core import errors as e
        assert hasattr(e, "VAL_NULL_REQUEST")
        assert hasattr(e, "CAP_REGISTRY_FROZEN")
        assert hasattr(e, "POL_ENGINE_FROZEN")
        assert hasattr(e, "AUD_PERSIST_ERROR")
