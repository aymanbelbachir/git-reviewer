# git-reviewer: threat model

git-reviewer reads untrusted code, runs it, and asks a language model about it. This document lists
what we protect, what we do not trust, who attacks, and for each threat the mitigation and the risk
that remains. Design details are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); requirements are
in [docs/SPEC.md](docs/SPEC.md).

Status: written in phase 1, before any code. Mitigations describe the design; the security-gate
skill checks them against the code as phases land. Residual risks and detection rates are updated
in phase 7.

## 1. Security principles

- **P1. Data is never instructions.** Diff content, repository files, LLM output and sandbox output
  are data. Nothing in them can choose an action.
- **P2. Deterministic code decides.** LLMs get no tools. They return strict JSON. The graph decides
  what runs, and only deterministic checks can allow anything.
- **P3. LLMs can only restrict.** The reviewer, the patch author and the guardians can add findings,
  alerts or blocks. Nothing they say removes a block or authorizes an effect.
- **P4. Fail closed.** Errors, timeouts, invalid output, missing Docker, oversized input: stop and
  say so. Never fall back to a weaker mode.
- **P5. Least privilege.** The sandbox has no network, no host files, no host env, no capabilities.
  Subprocesses get an empty environment and absolute binary paths.
- **P6. Local only.** The only network peer is a loopback Ollama.
- **P7. The user stays in control.** Nothing is written to the user's working tree without a typed
  confirmation. Nothing is ever staged, committed or pushed by the tool.

## 2. Assets

| ID | Asset | Property to protect |
|---|---|---|
| A1 | The user's source code | Confidentiality (must not leave the machine) |
| A2 | Secrets in the repository or environment (API keys, tokens, `.env`) | Confidentiality |
| A3 | SSH keys, cloud credentials, git credential helpers, keychain (`~/.ssh`, `~/.aws`, …) | Confidentiality |
| A4 | The user's machine: files, processes, the Docker daemon (root-equivalent) | Integrity, availability |
| A5 | The user's repository: working tree, index, `.git/config`, `.git/hooks` | Integrity |
| A6 | The review verdict itself (a false "all clear" is a successful attack) | Integrity |
| A7 | git-reviewer's code, configuration, dependencies and sandbox image | Integrity |

## 3. Untrusted inputs

| ID | Input | Controlled by |
|---|---|---|
| I1 | Diff content: code, comments, strings, file names | Attacker |
| I2 | Every file of the reviewed ref: tests, `conftest.py`, `pyproject.toml`, `setup.py`, `.gitattributes`, tool configs, symlinks | Attacker |
| I3 | LLM output: reviewer, patch author, guardians | Attacker, indirectly through I1/I2 |
| I4 | Everything produced in the sandbox: test and linter output, exit codes | Attacker |
| I5 | Ollama API responses | Local service; trusted for transport, not for content |
| I6 | The user's environment: env vars, `PATH`, git config, Docker context | The user; trusted but hardened against accidents |

## 4. Attackers

| ID | Attacker | Capabilities |
|---|---|---|
| AT1 | Malicious contributor whose branch or patch is reviewed | Full control of I1 and I2; influences I3 and I4 |
| AT2 | Booby-trapped content the user copied in (vendored code, snippets, generated files) | Same as AT1, without the user noticing |
| AT3 | Compromised dependency, tool binary, base image or model | Code execution inside git-reviewer or its tools |
| AT4 | Network attacker on the local network | Reaches services listening on non-loopback interfaces |

Out of scope: an attacker who already runs code as the user, a compromised OS or Docker installation,
and physical access.

## 5. Threats, mitigations, residual risks

Residual risk: **Low** (needs a bug in our controls or a 0-day), **Medium** (plausible with effort or
partly unmitigated), **High** (expected to happen), **Accepted** (known, documented, by design).

### 5.1 Prompt injection and LLM output

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| T-01 | Injection in the diff makes the reviewer miss or downplay a problem (false all clear, A6) | Nonce-delimited data block and "data only" system prompt; static tools are the source of truth and always shown; anti-injection guardian before (barrier + agent) and after (canary + cross-check with static findings) | **Medium**: LLM findings can still be manipulated; static findings cannot |
| T-02 | Injection makes the model take actions (exfiltrate, run commands, write files) | The model has no tools; output is strict JSON; routing reads typed state only; network limited to loopback Ollama | Low |
| T-03 | Injection steers the patch author into a backdoor | Structured edits only; deterministic path policy and AST checks; separate patch auditor; sandbox validation; full diff shown; typed confirmation; never committed | **Medium**: subtle logic changes in an allowed file can pass every check; the user's reading of the diff is the last line |
| T-04 | Malformed, oversized or schema-confusing model output | Constrained decoding plus our own `strict=True`, `extra="forbid"`, bounded lengths; no repair; failure = block | Low |
| T-05 | Findings pointing at lines outside the diff, misdirecting the user | Every `(file, line)` checked against the diff index; misses dropped and alerted | Low |
| T-06 | Terminal escape or markup injection through model text, file names or test output (clipboard writes, hidden text, fake links) | All displayed text stripped of C0/C1 and ANSI/OSC sequences, markup escaped, invisible characters shown as escapes, lengths capped | Low |
| T-07 | Trojan Source: bidi or invisible characters, Unicode tag smuggling, homoglyphs | Deterministic barrier blocks bidi, invisible and tag characters; mixed-script identifiers flagged | Low for bidi/invisible; **Medium** for homoglyphs |
| T-08 | Suppression markers or repo configs blind the static tools (`# noqa`, `# nosec`, `gitleaks:allow`, `.gitleaks.toml`, `.gitleaksignore`, `[tool.ruff]`, `ruff.toml`, `.bandit`) | ruff `--isolated --ignore-noqa`; bandit with our config and `--ignore-nosec`; gitleaks with `--config <ours>`, `--gitleaks-ignore-path <empty dir>`, `--ignore-gitleaks-allow`; newly added suppression markers are reported as findings | Low |

### 5.2 Running untrusted code

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| T-09 | Tests, `conftest.py`, pytest plugins, `.pth`/`sitecustomize.py` or build hooks run attacker code | Only inside the Docker sandbox (§8 of the architecture); execution guardian agent can refuse to run suspicious code at all | **Medium**: container escape through a kernel or Docker vulnerability; on macOS the Docker Desktop VM adds a layer |
| T-10 | Exfiltration over the network from the sandbox | `--network=none`, asserted on the argv before every run | Low |
| T-11 | Sandbox reads host secrets (`~/.ssh`, `~/.aws`, env vars, Docker socket, `.env`) | Only mount: the temp worktree, read-only. Untracked files such as `.env` are not in it. No env passthrough. All asserted | Low |
| T-12 | Resource exhaustion: infinite loop, fork bomb, memory bomb, disk fill, output flood | `--pids-limit`, `--memory` (no swap), `--cpus`, tmpfs size, wall-clock timeout then kill, output caps | Low |
| T-13 | Sandbox modifies the user's working tree or `.git` | Separate worktree, mounted read-only; fingerprint of the user's tree and `.git` control files compared before and after | Low |
| T-14 | A container survives the run (lingering attacker process) | `--rm`, kill and `rm -f` in `finally`, label-based check that it is gone, `doctor --cleanup` | Low |
| T-15 | A later code change weakens the Docker options (regression) | The argv is asserted field by field before each run; unit tests on the builder; security-gate skill | Low |
| T-16 | Docker missing, so tests run on the host | Refuse with exit code 4; no host code path exists | None (by design) |
| T-17 | `DOCKER_HOST` or the Docker context points to a remote daemon, sending the code away | Endpoint must be a local Unix socket, otherwise refuse | Low |
| T-34 | Test code fakes a pass (`os._exit(0)`, conftest hooks) | Test results are a quality signal only; they never authorize anything; the report says so | Accepted |

### 5.3 Patches and the user's repository

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| T-18 | Path traversal or symlinks make us read or write outside the repo; patches touch sensitive files (`.git/`, hooks, CI, dependency files, tool config) | Out-of-repo symlinks removed from the worktree copy; host reads use `lstat` and containment checks; patch policy: only the diff's files, NFC + casefold normalization (case-insensitive file systems), no `..`, absolute paths or symlinks, deny list; re-checked just before applying; `git apply` without `--unsafe-paths` | Low |
| T-19 | A patch weakens tests (assert removed, `skip`/`xfail`, relaxed tolerance, swallowed exceptions, changed expected values) | Deterministic AST checks plus the patch auditor; test infrastructure files are on the deny list | **Medium**: semantic weakening (a plausible new expected value) is hard to detect |
| T-20 | A patch is applied without consent, or the tool commits or pushes | Typed `yes` on an interactive TTY only; never in hook or JSON mode; target files must be unchanged since the review; no commit or push code exists (checked by security-gate) | Low |

### 5.4 Host integration

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| T-21 | Argument injection through refs or file names (`--output=…`, names starting with `-`) | No shell; argv lists; `--end-of-options` / `--` before untrusted values; refs resolved to object IDs first | Low |
| T-22 | Binary hijacking: a `git` or `docker` executable from the repo or a hostile `PATH` entry | Allowlist resolved once to absolute paths from fixed directories; relative `PATH` entries and binaries inside the repo refused | Low |
| T-23 | Our own git operations trigger repo-defined behavior: external diff drivers, textconv, filters, fsmonitor, hooks (`post-checkout` on worktree creation) | `--no-ext-diff --no-textconv`, `core.hooksPath=/dev/null`, `core.fsmonitor=false`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null` for operations on untrusted content | Low: the repository's own `.git/config` is trusted because the user controls it |
| T-27 | A repository file changes the tool's configuration (e.g. `ollama_url` pointing to a remote host) | No configuration is read from the repository in v1; tool config files are on the patch deny list | Low |
| T-28 | Hook installation overwrites an existing hook; the hook is bypassed, or reviews the wrong content (`git commit -a` uses a temporary index) | Never overwrite: refuse or chain (`--chain`), restore on uninstall; minimal readable script with an absolute path; `GIT_INDEX_FILE` passed through so the review sees exactly what is committed; `--no-verify` documented | Accepted: the hook is a convenience, not a security boundary |
| T-33 | Temp files exposed to other local users, or temp path races | `mkdtemp` (mode 0700), random names, cleanup in `finally` | Low |
| T-35 | An oversized diff is truncated and the payload hides past the cut | Hard limits; over a limit the status is "not reviewed" (blocks in block mode); never truncated silently | Low |
| T-36 | Payload hidden in binary or unanalyzable files | Listed as "not analyzed" in the report and flagged in block mode | **Medium** |

### 5.5 Confidentiality and network

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| T-24 | Code leaves the machine through the LLM endpoint: non-loopback `ollama_url`, an Ollama cloud model (local Ollama forwards the prompt), Ollama listening on `0.0.0.0` | URL must resolve only to loopback; the client ignores proxy variables (`trust_env=False`, explicit base URL); cloud models refused; warning when Ollama listens on all interfaces; `ollama_url` never read from the repository | Low: features of Ollama itself are outside our control |
| T-25 | LangChain / LangSmith tracing or telemetry sends prompts out | Tracing variables forced off and LangSmith keys removed before any LangChain import; tests assert it; test-wide socket guard fails on any non-loopback connection | Low |
| T-26 | Code or secrets end up in logs or saved reports | Logs carry allowlisted fields only; gitleaks values kept in memory and used to mask every displayed text; reports and logs written outside the working tree (state directory, mode 0600) | **Medium**: a model can paraphrase or split a secret, which exact-match masking misses |

### 5.6 Guardians, supply chain and development process

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| T-29 | Supply chain: malicious PyPI release, gitleaks binary, base image, GitHub Action, model weights, or a Claude Code plugin or skill used to develop the tool | Few dependencies; `uv.lock` with hashes and `--locked` installs; pip-audit and bandit in CI; Actions pinned by SHA; base image pinned by digest; gitleaks pinned with checksum; plugins limited to the official marketplace (pinned commits), listed in `.claude/settings.json` and approved by the user | **Medium**: a malicious release can land before advisories exist; model weights are opaque; plugins run with the coding agent's access to this repo |
| T-30 | A guardian is itself injected and answers "ok" | Guardians can only add restrictions; deterministic gates decide; fail-closed | Low for safety; detection recall is measured in §7 |
| T-31 | Guardian false positives block legitimate work | Warn mode; `--no-verify`; false-positive rate measured | Accepted (availability traded for safety) |
| T-32 | The repo's own malicious fixtures hurt the developer: pytest collects and runs them on the host, or a coding agent reading them follows their injected instructions | Fixtures are data files (`.diff`, `.json`, `.txt`), excluded from pytest, ruff, bandit and pyright; executed only inside the sandbox; `CLAUDE.md` and the security-guidance file tell agents to treat them as data | Low for host execution; **Medium** for coding agents (prompt injection against agents is an open problem) |

## 6. Requirement coverage

| Spec requirement | Threats | Architecture section |
|---|---|---|
| 1. Threat model first | all | this file |
| 2. Prompt injection | T-01 – T-08, T-30, T-35, T-36 | §5, §6, §10.1 |
| 3. Sandboxed execution | T-09 – T-17, T-33, T-34 | §8, §10.2 |
| 4. Patches | T-03, T-18 – T-20 | §10.3, §11 |
| 5. System commands | T-21 – T-23 | §6.1, §7 |
| 6. Network and privacy | T-24 – T-27 | §9, §12 |
| 7. Git hook | T-28 | §13 |
| 8. Supply chain | T-29 | §14 |
| 9. Security tests | T-32 and every attack above | §15 |
| Guardian rules | T-30, T-31 | §10 |

## 7. Guardian detection metrics

Measured by `scripts/eval_guardians.py` over `tests/guardians/datasets/` and written here by the
`red-team` skill. Detection rate = malicious samples rated `suspect` or `block`; false-positive
rate = clean samples rated `suspect` or `block`.

<!-- guardian-metrics:start -->
Not measured yet. Guardians are implemented in phases 3 to 5; datasets and measurements land in phase 7.
<!-- guardian-metrics:end -->

### Undetected cases

<!-- guardian-misses:start -->
None recorded yet.
<!-- guardian-misses:end -->

## 8. Accepted risks summary

- The LLM review can be manipulated (T-01, T-03). Static analysis and deterministic controls are the
  safety net; the LLM is an assistant, not an authority.
- A container escape needs a kernel or Docker vulnerability (T-09). Keeping Docker up to date is the
  user's responsibility; the execution guardian reduces exposure by refusing suspicious code.
- The pre-commit hook can be skipped with `--no-verify` (T-28).
- Sandbox test results can be faked by the code under test (T-34).

## 9. Reporting a vulnerability

This repository is private. Report issues directly to the owner; do not open a public issue.
