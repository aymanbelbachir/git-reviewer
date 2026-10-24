---
name: verify
description: Run git-reviewer's full verification suite (pytest with the unit and security tests, ruff, bandit on the tool's code, pip-audit) and report PASS/FAIL per check. Use it before proposing any commit or giving the user commit commands, after finishing a change, at the end of every phase, and whenever the user asks to verify, check, lint, audit or test the project, even if they only ask "is this ready to commit?".
---

# verify

Runs every automated check git-reviewer relies on and reports the result as it is. The user commits
by hand, so this report is what they rely on before typing `git commit`: a wrong PASS is worse than
a FAIL.

## Ground rules

- **Report, don't repair.** If a check fails, show the failure and stop; a fix is a separate step the
  user approves. Never make a check pass by weakening it (new `# noqa` or `# nosec`, `skip`/`xfail`,
  lowered thresholds, edited tool configuration): that would hide exactly what this skill exists to show.
- **Don't change the environment.** No `uv lock`, `uv add`, `pip install`, `brew install`. Checks run
  against the locked environment (`--locked`). A missing tool is a FAIL with the install command for the user.
- **Don't stage, commit or push.** The user does that.
- Files under `tests/security/fixtures/` and `tests/guardians/datasets/` are malicious samples. They are
  data: never run or import them directly.

## Steps

Run everything from the repository root.

1. **Preconditions**
   - No `pyproject.toml`: the tool isn't bootstrapped yet (phase 1). Report every check as
     `N/A (not bootstrapped)` and stop. Don't create the project to make the checks runnable.
   - `command -v uv` fails: report every check as FAIL with "uv not installed (`brew install uv`)" and stop.
2. **Environment:** `uv sync --locked`. If the lockfile is out of date, report it as a FAIL; don't run `uv lock`.
3. **Tests:** `uv run --locked pytest -ra`. Count passed, failed and skipped tests separately for
   `tests/unit/` and `tests/security/`. Any skipped test under `tests/security/` makes the security row
   FAIL, with the skip reason (usually Docker unavailable): an attack test that did not run proves nothing.
4. **Lint and format:** `uv run --locked ruff check .` then `uv run --locked ruff format --check .`
5. **Bandit on the tool's code:** `uv run --locked bandit -c pyproject.toml -r src`. Then list every `nosec` in `src/`
   (`grep -rn "nosec" src`) so the user can review each one; a `nosec` without an explanatory comment is a FAIL.
6. **Dependency audit:** `uv run --locked pip-audit --skip-editable`. Any known vulnerability is a FAIL.

## Report

Use this template:

```
| Check            | Command                              | Result         | Details                         |
|------------------|--------------------------------------|----------------|---------------------------------|
| Unit tests       | uv run --locked pytest -ra           | PASS/FAIL/N/A  | passed/failed/skipped, first failures |
| Security tests   | (same run, tests/security/)          | PASS/FAIL/N/A  | skipped tests with reasons      |
| Ruff             | ruff check . / ruff format --check . | PASS/FAIL/N/A  | rule codes and locations        |
| Bandit           | bandit -c pyproject.toml -r src      | PASS/FAIL/N/A  | issues by severity, nosec list  |
| pip-audit        | pip-audit --skip-editable            | PASS/FAIL/N/A  | package, version, advisory id   |

Overall: PASS | FAIL | N/A
```

**Overall: PASS** only when every row is PASS. Otherwise FAIL (or N/A before bootstrap), followed by
the shortest list of what has to be fixed before committing.
