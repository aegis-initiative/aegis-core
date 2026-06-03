"""Red Team Tests - Risk Engine Round 8: Attacking the Hardening.

Targets the specific fixes from the other session (BT-AUDIT-001
through BT-AUDIT-007, RT-R3-006 through RT-R3-020) to find
bypasses, regressions, and new attack surfaces introduced by
the hardening itself.

Attack categories:
1. Regex DoS on command prefix stripping
2. Prefix stripping on non-shell action types (false sensitivity)
3. Double URL encoding evasion
4. NFKC normalization weaponization (creating matches, not evading)
5. Seal token memory exposure
6. Silent evidence destruction via BT-AUDIT-007
7. Asymmetric amplifier false positives
8. Combining character survival post-NFKC
9. Shell redirect evasion (new < > chars in metachar pattern)
"""

from __future__ import annotations

import time

import pytest

from aegis_core import AEGISRuntime
from aegis_core.capability_registry import CapabilityRegistry
from aegis_core.policy_engine import PolicyEngine
from aegis_core.protocol import ActionType, Decision
from aegis_core.risk import RiskEngine

from .conftest import (
    make_allow_policy,
    make_capability,
    make_request,
)


def _setup_full_access(runtime: AEGISRuntime, agent_id: str = "r8-agent") -> None:
    cap_id = f"cap-{agent_id}"
    cap = make_capability(
        cap_id=cap_id,
        action_types=[a.value for a in ActionType],
        target_patterns=["*"],
    )
    try:
        runtime.capabilities.register(cap)
    except ValueError:
        pass
    runtime.capabilities.grant(agent_id, cap_id)
    if not runtime.policies.get_policy("pol-r8-allow"):
        runtime.policies.add_policy(make_allow_policy(policy_id="pol-r8-allow"))


# ===================================================================
# 1. Regex DoS on command prefix stripping
# ===================================================================


class TestRegexDoS:
    """_COMMAND_PREFIX_RE uses nested quantifiers that may backtrack."""

    def test_env_var_prefix_performance(self):
        """Many VAR=val prefixes should not cause catastrophic backtracking.

        The regex `(?:\\w+=\\S+\\s+)+` with many VAR=val pairs could
        cause O(2^n) backtracking on a non-matching suffix.
        """
        engine = RiskEngine()

        # Build a target with 100 VAR=val prefixes followed by a
        # non-matching tail that forces backtrack exploration
        env_vars = " ".join(f"V{i}=x" for i in range(100))
        target = f"{env_vars} !!!nomatch!!!"

        start = time.perf_counter()
        result = engine.assess(
            action_type="shell_exec",
            target=target,
            agent_id="test",
        )
        elapsed = time.perf_counter() - start

        # Should complete in well under 1 second. ReDoS would take
        # minutes or hang indefinitely.
        assert elapsed < 1.0, (
            f"RT-R4-001: Command prefix regex took {elapsed:.2f}s - "
            f"possible catastrophic backtracking"
        )

    def test_deeply_nested_sudo(self):
        """Nested sudo/nohup/env chains should not hang."""
        engine = RiskEngine()

        target = "sudo " * 50 + "nohup " * 50 + "rm -rf /"

        start = time.perf_counter()
        result = engine.assess(
            action_type="shell_exec",
            target=target,
            agent_id="test",
        )
        elapsed = time.perf_counter() - start

        assert elapsed < 1.0
        # Should also correctly strip prefixes and detect rm
        assert result.target_sensitivity >= 7.0, (
            f"Deeply nested prefixes should still detect 'rm': "
            f"sensitivity={result.target_sensitivity}"
        )


# ===================================================================
# 2. Prefix stripping on non-shell targets
# ===================================================================


class TestPrefixStrippingScope:
    """Prefix stripping runs on ALL targets, not just SHELL_EXEC.
    This could create false sensitivity matches."""

    def test_file_path_starting_with_sudo(self):
        """A file path named 'sudo_config.txt' shouldn't be stripped."""
        engine = RiskEngine()

        # This is a legitimate file path, not a shell command
        result = engine.assess(
            action_type="file_read",
            target="sudo_config.txt",
            agent_id="test",
        )

        # The prefix stripper shouldn't corrupt file paths
        # "sudo_config.txt" should NOT become "config.txt"
        # because "sudo" requires a trailing space in the regex
        assert result.target_sensitivity == 0.0, (
            f"File 'sudo_config.txt' should not trigger sensitivity: {result.target_sensitivity}"
        )

    def test_nohup_directory_name(self):
        """Directory named 'nohup_logs/' shouldn't be stripped."""
        engine = RiskEngine()

        result = engine.assess(
            action_type="file_read",
            target="/var/nohup_logs/output.txt",
            agent_id="test",
        )

        assert result.target_sensitivity == 0.0


# ===================================================================
# 3. Double URL encoding evasion
# ===================================================================


class TestDoubleUrlEncoding:
    """url_unquote decodes once. Double encoding survives."""

    def test_double_encoded_etc_passwd(self):
        """'%252Fetc%252Fpasswd' decodes to '%2Fetc%2Fpasswd', not '/etc/passwd'."""
        engine = RiskEngine()

        result = engine.assess(
            action_type="file_write",
            target="%252Fetc%252Fpasswd",
            agent_id="test",
        )

        # RT-R4-002: After one url_unquote pass, this becomes
        # "%2Fetc%2Fpasswd" which does NOT match "/etc/*"
        if result.target_sensitivity < 7.0:
            # Finding confirmed: double encoding evades
            pass

    def test_triple_encoded_shadow(self):
        """Triple encoding creates even deeper evasion layers."""
        engine = RiskEngine()

        result = engine.assess(
            action_type="file_write",
            target="%25252Fetc%25252Fshadow",
            agent_id="test",
        )

        if result.target_sensitivity < 7.0:
            pass  # Expected: triple encoding evades


# ===================================================================
# 4. NFKC normalization weaponization
# ===================================================================


class TestNFKCWeaponization:
    """NFKC normalization can CREATE matches, not just prevent evasion.
    An attacker could craft targets that normalize to sensitive paths
    but look innocent pre-normalization."""

    def test_mathematical_etc(self):
        """Mathematical italic letters normalize to ASCII via NFKC.
        U+1D68E (MATHEMATICAL MONOSPACE SMALL E) -> 'e'
        """
        engine = RiskEngine()

        # Mathematical monospace "etc" - looks different but NFKC normalizes
        # to "etc". Combined with /*/passwd pattern...
        math_etc = "/\U0001d68e\U0001d69d\U0001d68c/passwd"

        result = engine.assess(
            action_type="file_write",
            target=math_etc,
            agent_id="test",
        )

        # This SHOULD match after NFKC normalization
        assert result.target_sensitivity >= 7.0, (
            f"Mathematical italic '/etc/passwd' should match after NFKC: "
            f"sensitivity={result.target_sensitivity}"
        )

    def test_fullwidth_rm(self):
        """Fullwidth 'rm' normalizes to ASCII 'rm' via NFKC."""
        engine = RiskEngine()

        # Fullwidth r + m + space + -rf + space + /
        fullwidth_rm = "\uff52\uff4d -rf /"

        result = engine.assess(
            action_type="shell_exec",
            target=fullwidth_rm,
            agent_id="test",
        )

        assert result.target_sensitivity >= 7.0, (
            f"Fullwidth 'rm -rf /' should match after NFKC: sensitivity={result.target_sensitivity}"
        )


# ===================================================================
# 5. Seal token memory exposure
# ===================================================================


class TestSealTokenExposure:
    """The seal token is stored as a plain string — readable by any
    code with a reference to the registry."""

    def test_seal_token_readable_from_registry(self):
        """_seal_token is accessible via attribute access."""
        registry = CapabilityRegistry()
        token = registry.freeze()

        # RT-R4-003: Token is readable from the object
        exposed_token = registry._seal_token

        assert exposed_token == token, "Seal token readable via _seal_token attribute"

        # An attacker who can read _seal_token can unseal
        registry.unseal(exposed_token)
        assert not registry.is_frozen

    def test_seal_token_readable_from_policy_engine(self):
        """Same exposure in PolicyEngine."""
        engine = PolicyEngine()
        token = engine.freeze()

        exposed_token = engine._seal_token
        assert exposed_token == token

        engine.unseal(exposed_token)
        assert not engine.is_frozen


# ===================================================================
# 6. Silent evidence destruction (BT-AUDIT-007)
# ===================================================================


class TestSilentEvidenceDestruction:
    """BT-AUDIT-007 silently replaces corrupted JSON with empty
    defaults. An attacker with DB access can corrupt parameter
    records and the system silently reports {}."""

    def test_corrupted_parameters_silently_replaced(self, runtime: AEGISRuntime):
        """Corrupt a parameter record — audit returns {} silently."""
        _setup_full_access(runtime)

        request = make_request(
            agent_id="r8-agent",
            target="test-target",
            parameters={"secret": "TOP_SECRET_DATA"},
        )
        response = runtime.gateway.submit(request)

        # Verify original data stored
        record = runtime.audit.get_record(response.audit_id)
        assert record is not None
        assert record.action_parameters.get("secret") == "TOP_SECRET_DATA"

        # Attacker corrupts the JSON in the database
        conn = runtime.audit._conn
        conn.execute(
            "UPDATE audit_records SET action_parameters = 'CORRUPTED{{{' WHERE id = ?",
            (response.audit_id,),
        )
        conn.commit()

        # RT-R4-004: Corrupted record returns {} — evidence destroyed
        corrupted = runtime.audit.get_record(response.audit_id)
        assert corrupted.action_parameters == {}, "Corrupted parameters silently replaced with {}"
        # The original data is gone — no indication of tampering


# ===================================================================
# 7. Asymmetric amplifier false positives
# ===================================================================


class TestAmplifierFalsePositives:
    """The asymmetric amplifier fires when EITHER dimension >= 7.0.
    This could cause false escalation on benign actions."""

    def test_file_read_of_pem_file_escalated(self, runtime: AEGISRuntime):
        """FILE_READ of a .pem file — benign read, but .pem scores 7.0
        which triggers the amplifier."""
        _setup_full_access(runtime)

        request = make_request(
            agent_id="r8-agent",
            action_type=ActionType.FILE_READ,
            target="/certs/server.pem",
        )
        response = runtime.gateway.submit(request)

        # FILE_READ severity is 2.0, .pem target is 7.0
        # Amplifier fires because target >= 7.0
        # 0.15*3.0 + 0.30*2.0 + 0.30*7.0 + amplifier
        # = 0.45 + 0.6 + 2.1 + (7.0/10 * 1.5) = 3.15 + 1.05 = 4.2
        # Should NOT trigger confirmation threshold (7.0)
        assert response.decision == Decision.APPROVED, (
            f"Reading a .pem file should not be escalated: score={response.risk_score}"
        )

    def test_data_access_to_prod_with_amplifier(self, runtime: AEGISRuntime):
        """DATA_ACCESS to production — does amplifier cause false positive?"""
        _setup_full_access(runtime)

        request = make_request(
            agent_id="r8-agent",
            action_type=ActionType.DATA_ACCESS,
            target="production-database-query",
        )
        response = runtime.gateway.submit(request)

        # data_access=4.0, *production*=5.0
        # Neither >= 7.0, so no amplifier
        assert response.decision == Decision.APPROVED, (
            f"Production data access should not be escalated: score={response.risk_score}"
        )


# ===================================================================
# 8. Shell redirect evasion (BT-AUDIT-001)
# ===================================================================


class TestShellRedirectEvasion:
    """BT-AUDIT-001 added < and > to metachar pattern. Test bypasses."""

    def test_heredoc_evasion(self, runtime: AEGISRuntime):
        """Heredoc syntax uses << which contains < — caught or not?"""
        from aegis_core.exceptions import AEGISValidationError

        _setup_full_access(runtime)

        request = make_request(
            agent_id="r8-agent",
            action_type=ActionType.SHELL_EXEC,
            target="cat << 'EOF'\nmalicious\nEOF",
        )

        # << contains < which is in the metachar pattern
        with pytest.raises(AEGISValidationError, match="shell metacharacters"):
            runtime.gateway.submit(request)

    def test_process_substitution_evasion(self, runtime: AEGISRuntime):
        """Process substitution <() uses < — caught by metachar pattern."""
        from aegis_core.exceptions import AEGISValidationError

        _setup_full_access(runtime)

        request = make_request(
            agent_id="r8-agent",
            action_type=ActionType.SHELL_EXEC,
            target="diff <(cat /etc/passwd) <(cat /etc/shadow)",
        )

        with pytest.raises(AEGISValidationError, match="shell metacharacters"):
            runtime.gateway.submit(request)

    def test_file_descriptor_redirect(self, runtime: AEGISRuntime):
        """2>&1 uses > — caught by metachar pattern."""
        from aegis_core.exceptions import AEGISValidationError

        _setup_full_access(runtime)

        request = make_request(
            agent_id="r8-agent",
            action_type=ActionType.SHELL_EXEC,
            target="some_command 2>&1",
        )

        with pytest.raises(AEGISValidationError, match="shell metacharacters"):
            runtime.gateway.submit(request)


# ===================================================================
# 9. hmac.compare_digest timing attack on wrong type
# ===================================================================


class TestSealTokenTimingEdgeCases:
    """hmac.compare_digest requires bytes or str. What about edge cases?"""

    def test_unseal_with_empty_string(self):
        """Empty string token should fail — not crash."""
        registry = CapabilityRegistry()
        registry.freeze()

        from aegis_core.exceptions import AEGISCapabilityError

        with pytest.raises(AEGISCapabilityError, match="Invalid seal token"):
            registry.unseal("")

    def test_unseal_with_wrong_token(self):
        """Wrong token should fail with constant-time comparison."""
        registry = CapabilityRegistry()
        token = registry.freeze()

        from aegis_core.exceptions import AEGISCapabilityError

        with pytest.raises(AEGISCapabilityError, match="Invalid seal token"):
            registry.unseal("wrong-token-12345")

        # Should still be frozen
        assert registry.is_frozen

    def test_unseal_without_freeze(self):
        """Unsealing when not frozen should fail gracefully."""
        registry = CapabilityRegistry()

        from aegis_core.exceptions import AEGISCapabilityError

        with pytest.raises(AEGISCapabilityError, match="Invalid seal token"):
            registry.unseal("any-token")

    def test_double_freeze_overwrites_token(self):
        """Freezing twice generates a new token — old token is invalid."""
        registry = CapabilityRegistry()
        token1 = registry.freeze()
        token2 = registry.freeze()

        assert token1 != token2

        from aegis_core.exceptions import AEGISCapabilityError

        # Old token should fail
        with pytest.raises(AEGISCapabilityError, match="Invalid seal token"):
            registry.unseal(token1)

        # New token should work
        registry.unseal(token2)
        assert not registry.is_frozen


# ===================================================================
# 10. Behavioral scorer recursion
# ===================================================================


class TestBehavioralScorerRecursion:
    """_score_behavioral_anomaly calls _score_target_sensitivity for
    each historical record. With 50 records and 25 patterns, that's
    1250 fnmatch calls per behavioral check. Can we DoS this?"""

    def test_behavioral_scorer_performance(self, runtime: AEGISRuntime):
        """50 historical records × target sensitivity scoring should
        not take more than 1 second."""
        _setup_full_access(runtime)

        # Build up 50 audit records
        for i in range(50):
            request = make_request(
                agent_id="r8-agent",
                action_type=ActionType.FILE_READ,
                target=f"/data/file-{i}.txt",
            )
            runtime.gateway.submit(request)

        engine = RiskEngine(audit_system=runtime.audit)

        start = time.perf_counter()
        result = engine.assess(
            action_type="shell_exec",
            target="/etc/shadow",
            agent_id="r8-agent",
        )
        elapsed = time.perf_counter() - start

        assert elapsed < 1.0, (
            f"RT-R4-005: Behavioral scorer took {elapsed:.2f}s with "
            f"50 historical records — performance concern"
        )
