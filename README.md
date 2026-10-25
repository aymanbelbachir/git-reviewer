# git-reviewer

A 100% local code reviewer hooked into git: it analyzes your diffs with LangGraph and an Ollama model, and runs tests in an isolated Docker sandbox.

> Work in progress. The full specification is in [docs/SPEC.md](docs/SPEC.md).

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
