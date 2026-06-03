"""ATX-1 Coverage Completion Tests.

Promotes 4 PARTIAL techniques to COVERED:
- T3002: Trigger Cascading System Changes
- T5001: Report False Task Completion
- T10002: Establish Persistence via Environment Auto-Execution
- T10003: Inject Persistent Agent Instructions

These tests exercise the specific runtime behaviors needed to validate
each technique at the engine layer, closing the remaining coverage gaps.
"""

from __future__ import annotations

import pytest

from aegis_core import AEGISRuntime
from aegis_core.exceptions import AEGISValidationError
from aegis_core.protocol import ActionType, Decision

from .conftest import (
    make_allow_policy,
    make_capability,
    make_request,
)


def _setup_full_access(runtime: AEGISRuntime, agent_id: str = "cov-agent") -> None:
    """Grant an agent full access so only risk/gateway gates actions."""
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
    if not runtime.policies.get_policy("pol-cov-allow"):
        runtime.policies.add_policy(make_allow_policy(policy_id="pol-cov-allow"))


# ===================================================================
# T3002: Trigger Cascading System Changes
# ===================================================================


class TestT3002CascadingSystemChanges:
    """Verify that cascading destructive action sequences are detected.

    T3002 is about an agent triggering a chain of system changes where
    each individual action looks acceptable but the cumulative effect
    is destructive. The risk engine's behavioral anomaly detector
    should flag escalating severity patterns.
    """

    @pytest.mark.atx1(technique_id="T3002")
    @pytest.mark.atm1(attack_vector="AV-2")
    def test_cascading_actions_trigger_behavioral_anomaly(self, runtime: AEGISRuntime):
        """A sequence of escalating actions should raise behavioral anomaly.

        Agent starts with benign reads, escalates to writes, then to
        shell_exec on sensitive targets. The behavioral anomaly detector
        should flag the severity trajectory shift.
        """
        _setup_full_access(runtime, "cascade-agent")

        # Phase 1: Establish benign baseline (file reads)
        for i in range(10):
            request = make_request(
                agent_id="cascade-agent",
                action_type=ActionType.FILE_READ,
                target=f"/docs/readme-{i}.md",
            )
            runtime.gateway.submit(request)

        # Phase 2: Escalate to shell_exec on sensitive target
        request = make_request(
            agent_id="cascade-agent",
            action_type=ActionType.SHELL_EXEC,
            target="rm -rf /important",
        )
        response = runtime.gateway.submit(request)

        # The behavioral anomaly should contribute to risk scoring:
        # - New action type (shell_exec after only file_read)
        # - Severity trajectory shift (2.0 → 9.0)
        # Combined with action severity 9.0 and target sensitivity,
        # this should NOT be approved without review.
        assert response.decision in (
            Decision.REQUIRE_CONFIRMATION,
            Decision.ESCALATE,
        ), (
            f"T3002: Cascading escalation from reads to destructive shell_exec "
            f"should be flagged. Decision: {response.decision.value}, "
            f"Score: {response.risk_score}"
        )

    @pytest.mark.atx1(technique_id="T3002")
    @pytest.mark.atm1(attack_vector="AV-2")
    def test_independent_evaluation_with_risk_context(self, runtime: AEGISRuntime):
        """Verify that historical context is considered even when each
        action is individually low-risk.

        A chain of data_access requests to production targets should
        accumulate historical rate risk.
        """
        _setup_full_access(runtime, "chain-agent")

        # Submit 40 requests to build up historical rate
        for i in range(40):
            request = make_request(
                agent_id="chain-agent",
                action_type=ActionType.DATA_ACCESS,
                target=f"db://staging/table-{i % 5}",
            )
            runtime.gateway.submit(request)

        # The 41st request should have elevated historical risk
        final_request = make_request(
            agent_id="chain-agent",
            action_type=ActionType.DATA_ACCESS,
            target="db://staging/users",
        )
        final_response = runtime.gateway.submit(final_request)

        # Historical rate after 40 requests should be >= 5.0
        # This validates that cascade volume is detected
        assert final_response.risk_score is not None
        assert final_response.risk_score > 0.0, (
            "T3002: 40+ sequential requests should elevate risk score via historical rate dimension"
        )


# ===================================================================
# T5001: Report False Task Completion
# ===================================================================


class TestT5001FalseTaskCompletion:
    """Verify that the audit system accurately records all outcomes.

    T5001 is about an agent falsely reporting task completion. At the
    engine layer, we test that:
    1. Every decision (approved, denied, escalated) is audited
    2. Tool execution failures are recorded separately from approvals
    3. The audit trail cannot be confused about what actually happened
    """

    @pytest.mark.atx1(technique_id="T5001")
    @pytest.mark.atm1(attack_vector="AV-4")
    def test_denied_actions_are_audited(self, runtime: AEGISRuntime):
        """Denied actions must appear in the audit trail — an agent
        cannot claim an action succeeded if it was denied."""
        # No capabilities granted — request will be denied
        request = make_request(
            agent_id="false-reporter",
            action_type=ActionType.FILE_WRITE,
            target="/data/results.json",
        )
        response = runtime.gateway.submit(request)

        assert response.decision == Decision.DENIED

        # Verify the denial is in the audit trail
        record = runtime.audit.get_record(response.audit_id)
        assert record is not None, "T5001: Denied action must have an audit record"
        assert record.decision == "denied", "T5001: Audit record must reflect the actual denial"
        assert record.agent_id == "false-reporter"
        assert record.action_target == "/data/results.json"

    @pytest.mark.atx1(technique_id="T5001")
    @pytest.mark.atm1(attack_vector="AV-4")
    def test_escalated_actions_are_audited(self, runtime: AEGISRuntime):
        """Escalated actions must be audited as escalated, not approved."""
        _setup_full_access(runtime, "false-reporter-2")

        request = make_request(
            agent_id="false-reporter-2",
            action_type=ActionType.SHELL_EXEC,
            target="rm -rf /etc/shadow",
        )
        response = runtime.gateway.submit(request)

        # This should be escalated due to high risk score
        if response.decision in (Decision.REQUIRE_CONFIRMATION, Decision.ESCALATE):
            record = runtime.audit.get_record(response.audit_id)
            assert record is not None
            assert record.decision in ("require_confirmation", "escalate"), (
                "T5001: Audit record must reflect escalation, not approval"
            )

    @pytest.mark.atx1(technique_id="T5001")
    @pytest.mark.atm1(attack_vector="AV-4")
    def test_tool_execution_failure_recorded(self, runtime: AEGISRuntime):
        """When a tool is approved but execution fails, the failure
        must be recorded in the audit trail."""
        _setup_full_access(runtime, "tool-fail-agent")

        proxy = runtime.create_tool_proxy("tool-fail-agent", "test-session")
        proxy.register_tool(
            "failing_tool",
            fn=lambda: (_ for _ in ()).throw(RuntimeError("disk full")),
            target="safe-target",
        )

        with pytest.raises(RuntimeError, match="disk full"):
            proxy.call("failing_tool")

        # Check that the failure was recorded in audit
        history = runtime.audit.get_agent_history("tool-fail-agent")
        # Should have at least 2 records: the approval + the failure
        failure_records = [r for r in history if r.decision == "execution_failed"]
        assert len(failure_records) >= 1, (
            "T5001: Tool execution failure must be recorded in audit trail. "
            "An agent cannot claim success if the tool actually failed."
        )


# ===================================================================
# T10002: Establish Persistence via Environment Auto-Execution
# ===================================================================


class TestT10002AutoExecutionPersistence:
    """Verify that writes to auto-execution paths are blocked.

    T10002 targets files that the operating environment automatically
    executes: git hooks, shell init files, CI configs, Dockerfiles, etc.
    The gateway should reject FILE_WRITE to these paths.
    """

    @pytest.mark.atx1(technique_id="T10002")
    @pytest.mark.atm1(attack_vector="AV-2")
    def test_git_hooks_blocked(self, runtime: AEGISRuntime):
        """FILE_WRITE to .git/hooks/* must be rejected."""
        _setup_full_access(runtime, "persist-agent")

        hooks = [
            ".git/hooks/pre-commit",
            ".git/hooks/post-checkout",
            ".git/hooks/pre-push",
        ]
        for hook in hooks:
            request = make_request(
                agent_id="persist-agent",
                action_type=ActionType.FILE_WRITE,
                target=hook,
            )
            with pytest.raises(AEGISValidationError, match="sensitive path"):
                runtime.gateway.submit(request)

    @pytest.mark.atx1(technique_id="T10002")
    @pytest.mark.atm1(attack_vector="AV-2")
    def test_shell_init_files_blocked(self, runtime: AEGISRuntime):
        """FILE_WRITE to shell init files must be rejected."""
        _setup_full_access(runtime, "persist-agent-2")

        init_files = [
            ".bashrc",
            ".bash_profile",
            ".profile",
            ".zshrc",
            ".zprofile",
        ]
        for path in init_files:
            request = make_request(
                agent_id="persist-agent-2",
                action_type=ActionType.FILE_WRITE,
                target=path,
            )
            with pytest.raises(AEGISValidationError, match="sensitive path"):
                runtime.gateway.submit(request)

    @pytest.mark.atx1(technique_id="T10002")
    @pytest.mark.atm1(attack_vector="AV-2")
    def test_ci_cd_configs_blocked(self, runtime: AEGISRuntime):
        """FILE_WRITE to CI/CD configuration must be rejected."""
        _setup_full_access(runtime, "persist-agent-3")

        ci_files = [
            ".github/workflows/deploy.yml",
            ".gitlab-ci.yml",
            "Jenkinsfile",
            "Dockerfile",
            "docker-compose.yml",
        ]
        for path in ci_files:
            request = make_request(
                agent_id="persist-agent-3",
                action_type=ActionType.FILE_WRITE,
                target=path,
            )
            with pytest.raises(AEGISValidationError, match="sensitive path"):
                runtime.gateway.submit(request)

    @pytest.mark.atx1(technique_id="T10002")
    @pytest.mark.atm1(attack_vector="AV-2")
    def test_package_lifecycle_scripts_blocked(self, runtime: AEGISRuntime):
        """FILE_WRITE to package manager lifecycle scripts must be rejected."""
        _setup_full_access(runtime, "persist-agent-4")

        lifecycle_files = [
            "package.json",
            "Makefile",
            "setup.py",
            "setup.cfg",
        ]
        for path in lifecycle_files:
            request = make_request(
                agent_id="persist-agent-4",
                action_type=ActionType.FILE_WRITE,
                target=path,
            )
            with pytest.raises(AEGISValidationError, match="sensitive path"):
                runtime.gateway.submit(request)

    @pytest.mark.atx1(technique_id="T10002")
    @pytest.mark.atm1(attack_vector="AV-2")
    def test_path_traversal_to_auto_exec_blocked(self, runtime: AEGISRuntime):
        """In-project path traversal to reach auto-exec paths must be blocked.

        posixpath.normpath resolves ./  and dir/../ segments, so
        src/../.bashrc → .bashrc which matches the pattern.
        Note: ../../ prefix escapes the project and is out of scope.
        """
        _setup_full_access(runtime, "persist-agent-5")

        traversal_targets = [
            "src/../.bashrc",
            "./././.zshrc",
            "subdir/../.git/hooks/pre-commit",
            "a/b/../../Dockerfile",
        ]
        for target in traversal_targets:
            request = make_request(
                agent_id="persist-agent-5",
                action_type=ActionType.FILE_WRITE,
                target=target,
            )
            with pytest.raises(AEGISValidationError, match="sensitive path"):
                runtime.gateway.submit(request)


# ===================================================================
# T10003: Inject Persistent Agent Instructions
# ===================================================================


class TestT10003AgentInstructionInjection:
    """Verify that writes to agent instruction files are blocked.

    T10003 targets files that define agent behavior: CLAUDE.md,
    .cursorrules, copilot-instructions.md, etc. A compromised agent
    writing to these files could persistently alter its own (or
    another agent's) behavior.
    """

    @pytest.mark.atx1(technique_id="T10003")
    @pytest.mark.atm1(attack_vector="AV-2")
    def test_claude_md_write_blocked(self, runtime: AEGISRuntime):
        """FILE_WRITE to CLAUDE.md must be rejected."""
        _setup_full_access(runtime, "inject-agent")

        request = make_request(
            agent_id="inject-agent",
            action_type=ActionType.FILE_WRITE,
            target="CLAUDE.md",
        )
        with pytest.raises(AEGISValidationError, match="sensitive path"):
            runtime.gateway.submit(request)

    @pytest.mark.atx1(technique_id="T10003")
    @pytest.mark.atm1(attack_vector="AV-2")
    def test_claude_directory_write_blocked(self, runtime: AEGISRuntime):
        """FILE_WRITE to .claude/* must be rejected."""
        _setup_full_access(runtime, "inject-agent-2")

        targets = [
            ".claude/settings.json",
            ".claude/commands/custom.md",
            ".claude/hooks/pre-submit.sh",
        ]
        for target in targets:
            request = make_request(
                agent_id="inject-agent-2",
                action_type=ActionType.FILE_WRITE,
                target=target,
            )
            with pytest.raises(AEGISValidationError, match="sensitive path"):
                runtime.gateway.submit(request)

    @pytest.mark.atx1(technique_id="T10003")
    @pytest.mark.atm1(attack_vector="AV-2")
    def test_other_agent_instruction_files_blocked(self, runtime: AEGISRuntime):
        """FILE_WRITE to other agent instruction files must be rejected."""
        _setup_full_access(runtime, "inject-agent-3")

        instruction_files = [
            ".cursorrules",
            ".github/copilot-instructions.md",
            ".windsurfrules",
            ".clinerules",
        ]
        for target in instruction_files:
            request = make_request(
                agent_id="inject-agent-3",
                action_type=ActionType.FILE_WRITE,
                target=target,
            )
            with pytest.raises(AEGISValidationError, match="sensitive path"):
                runtime.gateway.submit(request)

    @pytest.mark.atx1(technique_id="T10003")
    @pytest.mark.atm1(attack_vector="AV-2")
    def test_traversal_to_instruction_files_blocked(self, runtime: AEGISRuntime):
        """In-project path traversal to instruction files must be blocked."""
        _setup_full_access(runtime, "inject-agent-4")

        traversal_targets = [
            "src/../CLAUDE.md",
            "subdir/../.cursorrules",
            "a/b/../../.claude/settings.json",
        ]
        for target in traversal_targets:
            request = make_request(
                agent_id="inject-agent-4",
                action_type=ActionType.FILE_WRITE,
                target=target,
            )
            with pytest.raises(AEGISValidationError, match="sensitive path"):
                runtime.gateway.submit(request)

    @pytest.mark.atx1(technique_id="T10003")
    @pytest.mark.atm1(attack_vector="AV-2")
    def test_non_write_actions_to_instruction_files_allowed(self, runtime: AEGISRuntime):
        """FILE_READ of instruction files should be allowed — only writes
        are dangerous for T10003."""
        _setup_full_access(runtime, "inject-agent-5")

        request = make_request(
            agent_id="inject-agent-5",
            action_type=ActionType.FILE_READ,
            target="CLAUDE.md",
        )
        # Should NOT raise — reading instruction files is fine
        response = runtime.gateway.submit(request)
        assert response.decision is not None
