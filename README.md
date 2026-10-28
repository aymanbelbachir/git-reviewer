# git-reviewer

A 100% local code reviewer hooked into git: it analyzes your diffs with LangGraph and an Ollama model, and runs tests in an isolated Docker sandbox.

Version 0.1.0, for Python projects (ruff, bandit, gitleaks, pytest). Your code never leaves your
machine: the only network calls go to Ollama on the loopback address. How it is built:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). What it protects against, and what it does not:
[SECURITY.md](SECURITY.md). The original specification: [docs/SPEC.md](docs/SPEC.md).

## What a review does

1. Reads the staged changes, or a commit range, within size limits.
2. Runs ruff, bandit and gitleaks on the changed files. Their findings are the source of truth.
3. Asks the local model to explain, prioritize and complete them. A finding the model places
   outside the added lines is dropped.
4. Three guardians watch for manipulation: text in the change that tries to steer the model, tests
   that try to harm your machine, and a proposed fix that smuggles something in. They can raise an
   alert or block, never allow.
5. If you ask, runs the project's tests in the sandbox (`--run-tests`) and proposes one fix
   (`--fix`).
6. Prints a report: each finding with its file, line, severity and explanation, followed by what the
   guardians decided.

## Quick start

After [installing](#installing) git-reviewer, pulling the [models](#models) and, for
`--run-tests`, building the [sandbox image](#running-the-tests-in-the-sandbox):

```
git-reviewer doctor
cd path/to/your/project
git add -p
git-reviewer review
git-reviewer install-hook
```

`doctor` checks git, Ollama, both models, gitleaks, Docker and the sandbox image. `review` reviews
what you staged. `install-hook` makes every `git commit` in this repository run a review first.

## Installing

git-reviewer needs [uv](https://docs.astral.sh/uv/), git 2.40 or later,
[gitleaks](https://github.com/gitleaks/gitleaks), [Ollama](https://ollama.com), and Docker for
`--run-tests`. Install it from a clone of this repository kept outside the repositories you review,
so that it runs with the exact dependency versions and hashes recorded in `uv.lock`:

```
git clone <this repository's URL> ~/.local/share/git-reviewer
cd ~/.local/share/git-reviewer
uv sync --locked --no-dev --no-editable
```

The command is then `~/.local/share/git-reviewer/.venv/bin/git-reviewer` (you can link it into
`~/.local/bin`), and `git-reviewer doctor` checks everything it needs. To upgrade, run `git pull`
in the clone, then the same `uv sync`. Avoid `uv tool install`: it does not use `uv.lock`, so it
installs whatever dependency versions are newest, without the recorded hashes.

git-reviewer refuses to run a scanner that sits inside the repository it reviews, since a branch
could replace it. So a development checkout cannot review itself: review a clone of it instead.

## Models

git-reviewer uses two local models through Ollama and never downloads them itself:

```
ollama pull qwen2.5-coder:7b
ollama pull qwen2.5-coder:14b
```

The 7b reviews the change; the 14b runs the guardians, the checks that watch for manipulation,
because it caught the most attacks in our measurements ([SECURITY.md](SECURITY.md) §7). The
guardians use a 12,288-token context (`guardian_context_tokens`) so that the 14b stays entirely on
the GPU of a 16 GB Mac; the reviewer keeps 32,768 (`model_context_tokens`). The two models do not
fit in 16 GB together, so Ollama swaps them during a review. On a 16 GB M1 Pro, the commits we timed
(53 and 116 added lines, mostly documentation) took about two minutes each; the guardians read
every added comment and documentation line, so changes with fewer of them go faster.

With less memory, use the 7b for both (it catches fewer attacks), in
`~/.config/git-reviewer/config.toml`:

```
guardian_model = "qwen2.5-coder:7b"
guardian_context_tokens = 32768
```

With 32 GB or more, `guardian_context_tokens = 32768` lets the guardians read more of a large
change in one review.

## Commands

| Command | What it does |
|---|---|
| `git-reviewer review` | Reviews the staged changes. |
| `git-reviewer review --range main..feature` | Reviews what `feature` changed since it branched from `main`. |
| `--run-tests` | Also runs the project's pytest and ruff in the sandbox. |
| `--fix` | Also proposes one fix, tested in the sandbox (implies `--run-tests`). |
| `--mode block` (default) or `--mode warn` | `block` fails on findings at or above the threshold; `warn` only reports. |
| `--format json` | Prints the report as JSON instead of text. |
| `git-reviewer doctor` | Checks everything git-reviewer needs, and whether git really runs the hook. |
| `git-reviewer install-hook`, `uninstall-hook` | See [Reviewing before each commit](#reviewing-before-each-commit). |
| `git-reviewer version` | Prints the version. |

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Reviewed, with nothing at or above `severity_threshold`. |
| 1 | Findings at or above `severity_threshold`, or requested tests that did not pass. |
| 2 | A security block or an internal error. Also a change that could not be reviewed, for example because it is too large. |
| 3 | A usage error: a wrong option or range, not a git repository, an invalid configuration. |
| 4 | Something is missing or failed: Ollama, a model, gitleaks, Docker, the sandbox image, a scanner or a git command. |

With `--mode warn`, findings, failed tests and a change too large to review exit 0 instead.
Security blocks and errors keep their codes.

## Settings

Settings are read from `~/.config/git-reviewer/config.toml` (or
`$XDG_CONFIG_HOME/git-reviewer/config.toml`), and a `GIT_REVIEWER_*` environment variable overrides
the file (for example `GIT_REVIEWER_REVIEWER_MODEL`). Nothing is read from the reviewed repository,
so a branch cannot change them. The file must be yours and not writable by group or others, and
every limit has a hard maximum.

| Setting | Default | What it controls |
|---|---|---|
| `ollama_url` | `http://127.0.0.1:11434` | Where Ollama listens. Only a loopback address is accepted. |
| `reviewer_model` | `qwen2.5-coder:7b` | The model that reviews the change. |
| `guardian_model` | `qwen2.5-coder:14b` | The model the guardians use. |
| `model_context_tokens` | `32768` | The reviewer model's context. |
| `guardian_context_tokens` | `12288` | The guardian model's context. |
| `ollama_timeout_seconds` | `120` | How long one model call may take. |
| `severity_threshold` | `"high"` | The lowest severity that fails a review in block mode: `info`, `low`, `medium`, `high` or `critical`. |
| `max_diff_bytes` | `1048576` | A larger change is not reviewed. |
| `max_files` | `200` | A change touching more files is not reviewed. |
| `max_line_chars` | `10000` | A change that adds a longer line is not reviewed. |
| `max_review_chars` | `60000` | If the numbered change and the scanner findings are longer, the model does not review it and the change is reported as not reviewed. |
| `sandbox_image` | `"git-reviewer-sandbox:0.1"` | The image the tests run in. |
| `sandbox_timeout_seconds` | `300` | How long each sandbox run (pytest, then ruff) may take. |

## Running the tests in the sandbox

`git-reviewer review --run-tests` runs the project's tests (pytest) and linter (ruff) in a Docker
container with no network, a non-root user and a read-only copy of the reviewed code. git-reviewer
never builds or pulls images (that would need the network), so build the sandbox image yourself,
once, from this repository:

```
docker build -t git-reviewer-sandbox:0.1 sandbox/
```

Without Docker, or without the image, `--run-tests` stops with exit code 4: tests never run on
your machine. `git-reviewer doctor` checks Docker and the image.

The image only contains pytest and ruff. If the reviewed project needs its own dependencies,
build a derived image from a requirements file you export from a ref you trust (for example the
base branch, never the branch under review), with hashes and wheels only so that no build script
runs, then point `sandbox_image` at it in `~/.config/git-reviewer/config.toml`:

```
FROM git-reviewer-sandbox:0.1
USER root
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/requirements.txt
USER 10001:10001
```

If the change under review modifies the dependencies, the tests still run with the trusted set.

## Proposing a fix

`git-reviewer review --fix` (which implies `--run-tests`) also proposes one patch, for the most
severe finding in a Python file of the change. The patch is written by your local model, checked by
deterministic rules (no network, process or dynamic code, no new dependency, no weakened test),
run in the sandbox (the tests must still pass, and the scanner must stop reporting the problem),
then checked by a separate patch auditor. Up to three attempts.

You see the full diff and type `yes` to apply it, in an interactive terminal only. It is written to
your working tree only: nothing is staged or committed, so review it with `git diff` and stage it
yourself. `--fix` is refused in a git hook, and `--format json` only shows the proposal.

## Reviewing before each commit

```
git-reviewer install-hook
```

installs a git pre-commit hook in the current repository: every `git commit` first reviews the
staged changes. In the default `block` mode, a finding at or above the severity threshold stops the
commit. With `--mode warn`, findings are only reported, but a security block (exit code 2) or a
missing Ollama or gitleaks still stops the commit. The hook does not run the sandbox tests.

- To skip the review for one commit: `git commit --no-verify`.
- To remove the hook: `git-reviewer uninstall-hook`.
- An existing pre-commit hook is never overwritten. `install-hook --chain` keeps it and runs it
  first; `uninstall-hook` puts it back. Hooks that look up their own name (husky v4, overcommit)
  cannot be chained: add the line `install-hook` prints to them instead.
- If git is set up to take its hooks from elsewhere (`core.hooksPath`, used by husky or the
  pre-commit framework), `install-hook` changes nothing and prints the line to add there.

The hook calls git-reviewer by its absolute path, so install git-reviewer outside the repository
you review (see [Installing](#installing)). If you move the repository or reinstall git-reviewer
elsewhere, run `install-hook` again. `git-reviewer doctor` shows whether git really
runs the hook.

## Security in short

- The models get no tools. They answer in a strict JSON format, an invalid answer is rejected and
  never repaired, and the program, not the model, decides what runs.
- Tests run only in the sandbox: no network, a non-root user, a read-only copy of the code, and
  limits on CPU, memory, processes and time. No Docker means no tests, never tests on your machine.
- A fix may only touch the reviewed files, never `.git/`, hooks, CI, dependency files or tool
  configuration. You see all of it, it is applied only after you type `yes`, and it is never
  staged or committed.
- Logs never contain your code or secrets, and LangChain and LangSmith tracing is off.

What it does not protect against (details in [SECURITY.md](SECURITY.md) §8):

- The model's review can be fooled. The scanners are the safety net: "no findings" does not prove
  a change is safe.
- The guardians were measured on a small set of plain attacks (60 malicious, 21 clean samples)
  that they were tuned on. They also raise false alerts, especially on changes that discuss
  security or AI prompts.
- `git commit --no-verify` skips the hook.
- Code under test can fake its own test results.
- Escaping the container needs a Docker or kernel flaw: keep Docker up to date.

## Development

```
uv sync --locked
uv run --locked pytest -ra
```

The sandbox attack tests in `tests/security/` need Docker and the sandbox image: without them they
are skipped locally, and CI fails instead. CI also runs ruff, bandit and pip-audit
([.github/workflows/ci.yml](.github/workflows/ci.yml)). To measure the guardians on their datasets:
`uv run --locked python scripts/eval_guardians.py`.

`tests/security/fixtures/` and `tests/guardians/datasets/` hold deliberately malicious samples.
They are data: never run them outside the sandbox.
