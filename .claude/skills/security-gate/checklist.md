# security-gate checklist

Every item needs implementation evidence and test evidence (`path:line`). Threat ids refer to
SECURITY.md; section numbers to docs/ARCHITECTURE.md. The phase in brackets is when the item is due.

## R1. Threat model [phase 1]
- R1.1 SECURITY.md lists assets, untrusted inputs and attackers, and gives a mitigation and a residual
  risk for every threat.
- R1.2 For modules that exist, the mitigations SECURITY.md claims match the code (spot-check at least five).

## R2. Prompt injection [phase 3]
- R2.1 The diff is wrapped in nonce-carrying delimiters; delimiter-like content inside it is escaped (§6.2).
- R2.2 System prompts say the block is data; no untrusted text is ever placed in a system prompt.
- R2.3 No model gets tools or function calling (look for `bind_tools`, `tools=`, `tool_choice`).
- R2.4 Model output is validated with `strict=True` and `extra="forbid"`, bounded fields, no repair or
  "fix" retries; invalid output is a failure / block, with a test feeding malformed output.
- R2.5 Graph routing reads typed state only; no model text decides what runs.
- R2.6 Findings whose file/line is not in the diff are dropped and raise an alert, with a test.
- R2.7 Untrusted text is sanitized before display (control, ANSI/OSC, bidi characters), with a test.
- R2.8 Static tools ignore repository config, suppressions and default excludes (files passed
  explicitly, git paths literal): ruff `--isolated --ignore-noqa`, bandit
  with our config, `--ignore-nosec` and an empty `--exclude=`, gitleaks with `--config <ours>` (no
  default path allowlist), an empty ignore path and `--ignore-gitleaks-allow`; the branch's
  `.gitleaksignore` is never exported; newly added suppression markers are reported; a scanner
  with no JSON output or a file it silently skipped is a failure. With tests (T-08).
- R2.9 Over a size limit the status is "not reviewed" (never silent truncation, including the
  guardian's input and the model's context window); executable binaries block, other binaries
  and unparsable files mean "not reviewed". With tests (T-35, T-36).
- R2.10 Only model failures and invalid output mean "not reviewed"; any other exception crashes
  (exit 2), never exit 0 in warn mode. A model answer cut off (`done_reason` not `stop`) or a
  prompt that overflowed the context is invalid output. With tests.

## R3. Sandboxed execution [phase 4]
- R3.1 The docker argv contains `--network=none`, asserted by the policy check, with a test.
- R3.2 Non-root `--user`.
- R3.3 `--read-only` with a tmpfs `/tmp` as the only writable location.
- R3.4 `--cpus`, `--memory` with equal `--memory-swap`, `--pids-limit`, and a host-side timeout that kills
  and removes the container.
- R3.5 No host environment: no `--env-file`, only allowlisted `--env NAME=VALUE` values; a bare
  `--env NAME` (which copies the host value) is rejected.
- R3.6 The only mount is the read-only sandbox copy, and the policy itself requires it to be
  `<temp>/git-reviewer-sandbox-*/tree` in a 0700 directory of the user: no home, `~/.ssh`, `~/.aws`,
  Docker socket, or the user's working directory. Tested.
- R3.7 Tests run on a read-only copy of the reviewed tree exported from git objects (no symlinks,
  no untracked files, nothing written to the user's `.git`), never on the working directory.
- R3.8 Docker unavailable means refusal (exit code 4) and no host code path, with a test.
- R3.9 Only a local Docker endpoint is accepted, and every call uses `--host unix://<validated socket>`
  with an empty `DOCKER_CONFIG`; the tool never builds or pulls images (no network); the image is
  run by its local image ID, resolved once per review and re-checked before each run.
- R3.11 The argv is checked against `sandbox.policy`'s own copy of the options before every run,
  including inside the runner itself, and a test pins that copy literally.
- R3.10 `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--pull=never`.

## R4. Patches [phase 5]
- R4.1 Patches may only touch files that are in the reviewed diff.
- R4.2 Traversal, absolute paths and symlinks are refused (`lstat`, containment check), after NFC
  normalization and casefolding.
- R4.3 Every entry of the deny list in docs/ARCHITECTURE.md §11 is enforced (that list is the single
  source; compare entry by entry), with a test per category.
- R4.4 The full diff is displayed (sanitized, never masked: a patch that would need masking is not
  offered) and applied only after a typed confirmation on a TTY; never in hook or JSON mode.
- R4.5 Targets are re-checked just before applying (TOCTOU: path rules, no symlink, exact reviewed bytes);
  the validated content is written through a new file and a rename, never through a symlink; no
  `git apply`.
- R4.6 No `git add`, `commit` or `push` anywhere in `src/`.

## R5. System commands [phase 2]
- R5.1 No `shell=True`, `os.system` or `os.popen` in `src/`.
- R5.2 Every subprocess goes through `proc.py`; no other module imports `subprocess`.
- R5.6 Only the effect modules listed in docs/ARCHITECTURE.md §2 write files (`open` for writing,
  `Path.write_*`, `os.replace`, `os.rename`, `os.chmod`, `os.symlink`), enforced by a test.
- R5.3 Binaries come from an allowlist resolved to absolute paths; relative PATH entries and binaries
  inside the reviewed repo are refused.
- R5.4 Child processes get a minimal explicit environment; untrusted arguments follow `--end-of-options` or `--`.
- R5.5 Git calls on untrusted content use `--no-ext-diff --no-textconv`, `core.hooksPath=/dev/null`,
  `core.fsmonitor=false`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_OPTIONAL_LOCKS=0`.

## R6. Network and privacy [phase 2, logging in phase 3]
- R6.1 The Ollama URL must resolve only to loopback, with a test. The client ignores proxy variables
  (`trust_env=False`, explicit `base_url`), tested with `HTTPS_PROXY` set.
- R6.2 A warning is shown when Ollama listens on `0.0.0.0`.
- R6.3 Ollama cloud models are refused.
- R6.4 LangChain/LangSmith tracing is forced off before any LangChain import, with a test.
- R6.5 No other network client in `src/` (`requests`, `urllib`, `httpx`, `socket` outside the Ollama client).
- R6.6 Logs carry allowlisted fields only; secrets are masked in all output, with a test. Reports are
  printed only: no report or log file is written, least of all inside the working tree.
- R6.7 No configuration is read from the reviewed repository.

## R7. Git hook [phase 6]
- R7.1 Installing never overwrites an existing hook (refuse or chain), with a test.
- R7.2 The hook script is minimal and readable and calls the binary by absolute path.
- R7.3 Blocking and warning modes exist.
- R7.4 `--no-verify` is documented.
- R7.5 In hook mode the review reads the index git is committing (`GIT_INDEX_FILE` passed through),
  with a test using `git commit -a`.
- R7.6 The hook never runs a program from the repository (binary outside it by file identity, as given
  and resolved, not writable by others), and refuses symlinked hooks, a symlinked hooks directory,
  `core.hooksPath` (even empty) and configuration from the environment, with tests.
- R7.8 Only a hook exactly as git-reviewer writes it is replaced or removed; a parked chained hook is
  never ignored; `doctor` warns when git would not run the hook.
- R7.7 Warn mode never lets a security block (exit 2) through.

## R8. Supply chain [phase 2]
- R8.1 `uv.lock` is committed; runtime dependencies are minimal (list them, flag anything unexpected).
- R8.2 Installs use `--locked` (hashes come from `uv.lock`), in CI and in the user install the
  README documents.
- R8.3 CI runs pip-audit and bandit on `src/`; GitHub Actions pinned by SHA; workflow permissions read-only.
- R8.4 The sandbox base image is pinned by digest [phase 4].

## R9. Security tests [phase 7, partial earlier]
- R9.1 Diff with a prompt injection in a comment.
- R9.2 Patch with path traversal.
- R9.3 Test that attempts network access.
- R9.4 Test that reads `~/.ssh`.
- R9.5 Infinite loop.
- R9.6 Fork bomb.
- R9.7 Symlink pointing outside the repository.
- R9.8 Each test asserts that the attack fails, not just that it ran.
- R9.9 Malicious fixtures cannot be collected or imported on the host (`norecursedirs`, non-`.py` names,
  excluded from ruff/bandit/pyright).

## G0. Rules common to all guardians [phase 3]
- G0.1 Combination is monotonic: a guardian can only add an alert or a block and cannot lift a
  deterministic block.
- G0.2 Fail-closed: exception, timeout, invalid JSON or schema violation gives `block`, with tests.
- G0.3 Isolation: own system prompt, no tools, no reviewer history.
- G0.4 Strict output schema `{verdict: ok|suspect|block, reasons, lines}`.
- G0.5 The guardian model and its context window are configurable separately from the reviewer's,
  and every guardian call is sized against the guardian's own context.
- G0.6 Every decision is logged without code or secrets and shown in the security report.

## G1. Anti-injection guardian [phase 3]
- G1.1 Barrier: bidi and Unicode tag characters and a carriage return inside a line block;
  other invisible characters, other control characters (not a tab), Unicode line or paragraph
  separators and words mixing letters of different scripts are suspect.
- G1.2 Barrier: long base64/hex strings that decode to readable text flagged, decoded text re-scanned.
- G1.3 Barrier: AI-addressed phrases detected after normalization, English and French at least,
  including instructions split across lines and imitations of the data delimiters.
- G1.4 Agent classifies the flagged passages and every added comment, string and non-Python line,
  and returns line references. It sees every flagged passage (in batches; what it cannot see whole
  blocks); other lines it has no room for raise an alert. It may block a flagged passage; on the
  other lines its verdict is capped at an alert, while a guardian failure still blocks. With tests.
- G1.5 Canary token in the reviewer system prompt; its presence in the output blocks, also when
  JSON-escaped, re-cased, split by punctuation or written in fullwidth letters.
- G1.6 Cross-check: a static finding ignored or downgraded by the reviewer raises a probable-injection alert.

## G2. Execution guardian [phase 4]
- G2.1 The docker argv is asserted field by field before every run; one deviation means no run.
- G2.2 The agent reads tests, `conftest.py`, `setup.py`, `pyproject.toml` and fixtures from the diff and
  flags network, subprocess, out-of-repo reads, env access, `eval`/`exec`, obfuscation.
- G2.3 The user's working directory fingerprint (content hashes, including `.git/index`, `.git/config`
  and `.git/hooks/`) is identical before and after the run.
- G2.4 The container is verified stopped and removed.

## G3. Patch auditor [phase 5]
- G3.1 Separate from the patch author; receives only the finding and the patch.
- G3.2 Checks scope, network calls, dependencies, obfuscation, unexpected imports.
- G3.3 Checks test weakening: removed asserts, skip/xfail, relaxed thresholds, swallowed exceptions.
- G3.4 Deterministic path rules run before it and have the final say.

## G4. Guardian measurements [phase 7]
- G4.1 At least 20 malicious samples per guardian plus clean samples (a test enforces it).
- G4.2 SECURITY.md §7 shows detection and false-positive rates per guardian, and the undetected cases.
- G4.3 `scripts/eval_guardians.py` exists with tests; the malicious samples come from the user
  (CLAUDE.md), and SECURITY.md never contains a payload.
