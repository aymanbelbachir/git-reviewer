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
| T-01 | Injection in the diff makes the reviewer miss or downplay a problem (false all clear, A6) | Nonce-delimited data block and "data only" system prompt; static tools are the source of truth and always shown; anti-injection guardian before (barrier + agent, which sees every flagged passage in batches or blocks) and after (canary, also matched when escaped or re-cased, + cross-check with static findings); the prompt must fit the model context with room for the answer, checked before and after the call, since Ollama silently drops what does not fit | **Medium**: LLM findings can still be manipulated (the phrase lists can be evaded, and the guardian agent only runs when the barrier flags something); static findings cannot |
| T-02 | Injection makes the model take actions (exfiltrate, run commands, write files) | The model has no tools; output is strict JSON; routing reads typed state only; network limited to loopback Ollama | Low |
| T-03 | Injection steers the patch author into a backdoor | Structured edits on the finding's file only (we build the diff); a canary in the author's prompt (a leak blocks); deterministic path policy and AST checks that run before anything executes and cannot be overruled (encoding declarations refused, files parsed as Python reads them, import aliases resolved); execution guardian, sandbox validation (tests must pass, and the scanner must stop reporting the finding); a separate patch auditor that sees only the finding and the patch; full diff shown, never masked (a patch whose file, content or diff contains a detected secret value is not offered, so a crafted multi-line "secret" cannot hide a line from the approved diff), with the author's explanation labelled; typed confirmation; never staged or committed | **Medium**: subtle logic changes in an allowed file can pass every check, and the deterministic checks cannot follow every indirection (`o = os; o.system(...)`); the sandbox, the auditor and the user's reading of the diff are the remaining lines |
| T-04 | Malformed, oversized or schema-confusing model output | Constrained decoding plus our own `strict=True`, `extra="forbid"`, bounded lengths; no repair; failure = block | Low |
| T-05 | Findings pointing at lines outside the diff, misdirecting the user | Every `(file, line)` checked against the diff index; misses dropped and alerted | Low |
| T-06 | Terminal escape or markup injection through model text, file names or test output (clipboard writes, hidden text, fake links) | All displayed text stripped of C0/C1 and ANSI/OSC sequences, markup escaped, invisible characters shown as escapes, lengths capped | Low |
| T-07 | Trojan Source: bidi or invisible characters, Unicode tag smuggling, homoglyphs; code hidden from git's view of the lines (lone carriage return, `utf-7` encoding declaration) | Deterministic barrier blocks bidi and tag characters and a carriage return inside a line, flags other invisible characters; NFKC folds fullwidth forms. Static analysis blocks a non-UTF-8/ASCII/Latin-1 encoding declaration and any scanner finding beyond git's last line. Mixed-script (homoglyph) detection is not implemented yet | Low for bidi/invisible; **Medium** for homoglyphs |
| T-08 | Suppression markers or repo configs blind the static tools (`# noqa`, `# nosec`, `gitleaks:allow`, `.gitleaks.toml`, `.gitleaksignore`, `[tool.ruff]`, `ruff.toml`, `.bandit`) | ruff `--isolated --ignore-noqa --no-respect-gitignore` with every file passed explicitly (its default excludes such as `dist/` hide nothing); bandit with explicit files, `--ignore-nosec` and an empty `--exclude=` (its default excludes match `.github/` and `CVSexport.py` by substring), with a check that it analyzed every file; gitleaks with `--config <ours>` (without the default path allowlist that skips `node_modules/`, lockfiles and PDFs), `--gitleaks-ignore-path <empty dir>`, `--ignore-gitleaks-allow`, and the branch's `.gitleaksignore` never exported; Python files found by shebang too; a scanner with no JSON output is a failure, never "no findings"; git paths always literal (`--literal-pathspecs`, so a file named `:(exclude)x.py` cannot drop `x.py`); newly added suppression markers and scanner-config edits are reported as findings | Low (a scanner finding reported on an unchanged line, such as bandit's start line of a multi-line call whose argument changed, is dropped; deferred: use the finding's full line range) |

### 5.2 Running untrusted code

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| T-09 | Tests, `conftest.py`, pytest plugins, `.pth`/`sitecustomize.py` or build hooks run attacker code | Only inside the Docker sandbox (§8 of the architecture); the execution guardian agent reads the changed test infrastructure first (pytest config files included) and can refuse to run it at all (its failure also refuses); the reviewed code is importable only after the standard library and pytest (`python -P` + a `.pth` in the image), so a `pytest.py` in the repository cannot replace pytest and fake a pass | **Medium**: container escape through a kernel or Docker vulnerability; on macOS the Docker Desktop VM adds a layer. Known gap, for the phase 7 audit: pytest also runs `>>>` lines in `test*.txt` files as doctests, and the execution guardian does not read those files yet (they still run only in the sandbox) |
| T-10 | Exfiltration over the network from the sandbox | `--network=none`, asserted on the argv before every run | Low |
| T-11 | Sandbox reads host secrets (`~/.ssh`, `~/.aws`, env vars, Docker socket, `.env`) | Only mount: a read-only copy of the reviewed tree exported from git objects, so untracked files such as `.env` are never in it. No env passthrough (`HOME=/tmp` and two Python variables only); empty private `DOCKER_CONFIG` for the docker CLI. All asserted; Docker-backed attack tests read `~/.ssh`, the host home and the environment from inside | Low |
| T-12 | Resource exhaustion: infinite loop, fork bomb, memory bomb, disk fill, output flood | `--pids-limit=256`, `--memory=1g` with equal `--memory-swap` (no swap), `--cpus=1`, 256 MiB tmpfs, read-only root, `timeout --signal=KILL` inside the container plus a host-side timeout, 4 MiB output cap; each attack has a Docker-backed test | Low |
| T-13 | Sandbox modifies the user's working tree or `.git` | The working directory is never mounted (the copy comes from git objects, nothing is written to `.git`); fingerprint (content hashes) of tracked and untracked non-ignored files, `HEAD`, `index`, `config.worktree`, and the common directory's `config`, `hooks/` and `info/` (correct in linked worktrees too) compared before and after: any change, or any file that cannot be read, blocks | Low (ignored files are not fingerprinted) |
| T-14 | A container survives the run (lingering attacker process) | `--rm`, the in-container timeout, `docker rm -f` in `finally`, label-based check that no container of the run remains (block otherwise); `doctor` lists leftovers | Low |
| T-15 | A later code change weakens the Docker options (regression) | The argv is checked before every run against `sandbox.policy`'s own copy of the options (exact match, nothing extra allowed), once by the execution guardian and again inside the runner; the mount source must be the private sandbox copy (`<temp>/git-reviewer-sandbox-*/tree`, 0700, owned by the user) whatever the builder planned; a test pins the option list literally | Low |
| T-16 | Docker missing, so tests run on the host | Refuse with exit code 4; no host code path exists | None (by design) |
| T-17 | `DOCKER_HOST` or the Docker context points to a remote daemon, sending the code away | Endpoint resolved once (DOCKER_HOST, else the current context, else `/var/run/docker.sock`) and must be a `unix://` socket owned by root or the user, in a directory others cannot write; every call gets `--host unix://<that socket>`; remote endpoints exit 2 | Low |
| T-34 | Test code fakes a pass (`os._exit(0)`, conftest hooks) | Test results are a quality signal only; they never authorize anything; the report says so ("their output is untrusted"). Failing tests only make block mode exit 1; a pytest exit 0 without its "passed" summary is an error; patches may not add `os._exit` | Accepted |

### 5.3 Patches and the user's repository

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| T-18 | Path traversal or symlinks make us read or write outside the repo; patches touch sensitive files (`.git/`, hooks, CI, dependency files, tool config) | Symlinks and submodules are never materialized in the scanner and sandbox copies (reported in the notes); a path with a `.git` component (also `.GIT`, `.git.`) stops the review, and one elsewhere in the tree copied to the sandbox is a security block; host reads use `lstat` and containment checks; patch policy: only the diff's files, NFC + casefold normalization (case-insensitive file systems), no `..`, absolute paths or symlinks, deny list; re-checked just before applying; the validated content written through an `O_EXCL|O_NOFOLLOW` temporary file and a rename after re-checking the file's identity, no git command | Low |
| T-19 | A patch weakens tests (assert removed, `skip`/`xfail`, relaxed tolerance, swallowed exceptions, changed expected values) | Deterministic AST checks (no removed or changed assertion or test, no new skip/xfail/SkipTest/skipTest, no new early return, raise or constant condition in a test, no catch-all `except`) plus the patch auditor; test infrastructure files are on the deny list; the patched tests must pass in the sandbox | **Medium**: semantic weakening (a plausible new expected value) is hard to detect |
| T-20 | A patch is applied without consent, or the tool commits or pushes | Typed `yes` on an interactive TTY only; refused in hook mode, never applied in JSON mode; target file must be byte-identical to the reviewed version; written to the working tree only (new file + rename, no git command); a structural test forbids `git add`, `commit`, `push` and other index-changing commands in the code | Low |

### 5.4 Host integration

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| T-21 | Argument injection through refs or file names (`--output=…`, names starting with `-`) | No shell; argv lists; `--end-of-options` / `--` before untrusted values; refs resolved to object IDs first | Low |
| T-22 | Binary hijacking: a `git` or `docker` executable from the repo or a hostile `PATH` entry | Allowlist resolved once to absolute paths from fixed directories; relative `PATH` entries and binaries inside the repo refused | Low |
| T-23 | Our own git operations trigger repo-defined behavior: external diff drivers, textconv, filters, fsmonitor, hooks (`post-checkout` on worktree creation) | `--no-ext-diff --no-textconv`, `core.hooksPath=/dev/null`, `core.fsmonitor=false`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null` for operations on untrusted content | Low: the repository's own `.git/config` is trusted because the user controls it |
| T-27 | A repository file changes the tool's configuration (e.g. `ollama_url` pointing to a remote host) | No configuration is read from the repository in v1; tool config files are on the patch deny list | Low |
| T-28 | Hook installation overwrites an existing hook, a file it points to or a hook edited by hand; the hook silently never runs (`core.hooksPath` set by husky or the pre-commit framework, even empty; a chained hook dropped or parked); the hook runs a program the reviewed branch or another user controls; the hook is bypassed, or reviews the wrong content (`git commit -a` uses a temporary index; a file staged while a manual review runs) | Never overwrite: refuse or chain (`--chain`, only an executable hook that does not read `$0`), restore on uninstall in one rename; created through a new file and a hard link, which fails if the name exists; only a hook byte-identical to what git-reviewer writes is replaced or removed; symlinked hooks or hooks directory refused; `core.hooksPath` from any configuration file (or configuration from the environment) refused with the exact manual line; a parked chained hook is always reported with the `mv` that restores it; minimal readable script calling git-reviewer by a single-quoted absolute path outside the repository (by file identity, as given and resolved), not writable by others; `doctor` warns when git would not run the hook; `GIT_INDEX_FILE` passed through so the review sees exactly what is committed (tested with real `git commit -a`, `git commit <paths>` and a linked worktree); staged mode checks that the index is unchanged before scanning and before copying it to the sandbox; warn mode never downgrades security blocks; `--no-verify` documented | Accepted: the hook is a convenience, not a security boundary; `--no-verify`, or editing the hook, skips it. Not detected: a `core.hooksPath` that only another git build reads (e.g. Apple's `/usr/bin/git` reads `/etc/gitconfig`, Homebrew's git its own), or that another linked worktree sets in its `config.worktree` |
| T-33 | Temp files exposed to other local users, or temp path races | `mkdtemp` (mode 0700), random names, cleanup in `finally` | Low |
| T-35 | An oversized diff is truncated and the payload hides past the cut (in git-reviewer, in the guardian's input, or by Ollama when the prompt exceeds the context window) | Hard limits; over a limit the status is "not reviewed" (blocks in block mode); guardian passages are batched, and too many batches block; prompt size checked against the context before and after the model call; never truncated silently | Low |
| T-36 | Payload hidden in binary or unanalyzable files, including files a `.gitattributes` marks `-diff` or `binary` | git reads attributes from the empty tree, so the repository cannot turn its own code into "binary"; executable binaries (`.pyc`, `.so`, `.pth`, wheels...) are blocked; other binaries and files bandit cannot parse make the status "not reviewed" (exit 2 in block mode); the report shows how many files each scanner analyzed | **Medium** |

### 5.5 Confidentiality and network

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| T-24 | Code leaves the machine through the LLM endpoint: non-loopback `ollama_url`, an Ollama cloud model (local Ollama forwards the prompt), Ollama listening on `0.0.0.0` | URL must resolve only to loopback; the client ignores proxy variables (`trust_env=False`, explicit base URL); cloud models refused; warning when Ollama listens on all interfaces; `ollama_url` never read from the repository | Low: features of Ollama itself are outside our control |
| T-25 | LangChain / LangSmith tracing or telemetry sends prompts out | Tracing variables forced off and LangSmith keys removed before any LangChain import; tests assert it; test-wide socket guard fails on any non-loopback connection | Low |
| T-26 | Code or secrets end up in logs or saved reports | Logs carry allowlisted fields only; gitleaks values kept in memory and used to mask every displayed text; bandit's hardcoded-password messages, which quote the value, are replaced; reports and logs written outside the working tree (state directory, mode 0600) | **Medium**: a model can paraphrase or split a secret, which exact-match masking misses |

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
