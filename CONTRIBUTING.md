# Contributing to AEGIS Core

Thanks for your interest in contributing. This document covers the conventions
and expectations for contributions to aegis-core.

## Scope

aegis-core is the reference Python implementation of the
[AEGIS Governance Protocol (AGP-1)](https://github.com/aegis-initiative/aegis-governance).
It implements the `ACTION_PROPOSE` → `ACTION_DECIDE` → `ACTION_EXECUTE`
decision pipeline with capability, policy, and risk evaluation stages.

Contributions that align with the existing AGP-1 spec are welcome.
Contributions that propose protocol extensions, new evaluation stages, or
interface changes should start with an issue or RFC in
[aegis-governance](https://github.com/aegis-initiative/aegis-governance)
— the protocol canonical source — before code lands here.

## Developer Certificate of Origin (DCO)

All commits must be signed off per the
[Developer Certificate of Origin](https://developercertificate.org/). Add
`Signed-off-by: Your Name <your.email@example.com>` to each commit, or use
`git commit -s`.

We have not adopted a Contributor License Agreement (CLA) at this time. DCO
is sufficient.

## Workflow

1. Fork the repository and clone your fork.
2. Create a feature branch from `main` using a conventional prefix:
   `feat/your-feature`, `fix/your-bugfix`, or `docs/your-docs`.
3. Make your changes.
4. Run tests from the package root:

   ```bash
   cd core-py
   python -m pytest
   ```

5. Run lint and type checks:

   ```bash
   cd core-py
   ruff check .
   mypy .
   ```

6. Commit with sign-off: `git commit -s`.
7. Push and open a pull request against `main`.

`main` is protected — all changes ship via PR with at least one approving
review.

## Commit message conventions

We use [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | Use for |
|---|---|
| `feat:` | new features |
| `fix:` | bug fixes |
| `docs:` | documentation-only changes |
| `chore:` | tooling, refactors, dependency bumps |
| `test:` | test-only changes |
| `ci:` | CI workflow changes |

Keep the subject line under 72 characters. Include a body paragraph when the
change warrants explanation, separated from the subject by a blank line.

## Code style

- **Python:** PEP 8, enforced by [ruff](https://github.com/astral-sh/ruff).
  Type hints on all public APIs. Enforced by `mypy --strict`.
- **Docstrings:** every public module, class, and function. Each module's
  top-level docstring should name its role in the AGP-1 pipeline.
- **Comments:** sparingly. Explain *why*, not *what* — identifiers and
  structure should carry the *what*.

## Testing

All new features and bug-fix PRs require tests. The full suite (currently
419 tests) runs on every PR via CI.

- Unit tests for every scoring and evaluation function.
- Integration tests for gateway, decision engine, and audit pipeline.
- Adversarial (red/blue) coverage in `core-py/tests/security/`.

New governance logic should land with tests that demonstrate both the
intended-allow path and at least one intended-deny path.

## Reporting security issues

Please do not file public issues for security-relevant findings. Contact the
maintainers via the `aegis-initiative` GitHub org contact methods and we
will coordinate responsible disclosure.

## Licensing

By contributing to aegis-core, you agree that your contributions are
licensed under the [Apache License 2.0](LICENSE).
