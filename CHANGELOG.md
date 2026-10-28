# Changelog

## 0.1.0 (2026-10-28)

The first complete version: everything in [docs/SPEC.md](docs/SPEC.md), for Python projects.

- `git-reviewer review` reviews the staged changes or a `--range`: ruff, bandit and gitleaks first,
  then a local Ollama model that explains and prioritizes, with every finding tied to a line of the
  diff.
- `--run-tests` runs pytest and ruff in a Docker sandbox with no network, a non-root user, a
  read-only copy of the code and resource limits; without Docker, tests do not run.
- `--fix` proposes one patch, checked by deterministic rules, tested in the sandbox, audited
  separately, and applied only after you type `yes`.
- Three guardians (anti-injection, execution, patch auditor) on `qwen2.5-coder:14b`, measured on
  60 malicious and 21 clean samples ([SECURITY.md](SECURITY.md) §7).
- `install-hook` and `uninstall-hook` for a pre-commit hook in block or warn mode, never
  overwriting an existing hook.
- `doctor` checks git, Ollama, the models, gitleaks, Docker and the sandbox image.
- A threat model ([SECURITY.md](SECURITY.md)), a security test suite with malicious fixtures, and
  CI running the tests, ruff, bandit and pip-audit.
