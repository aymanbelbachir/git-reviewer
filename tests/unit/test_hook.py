"""Hook installation: never overwrite, chain and restore, refuse what git would not run
(docs/ARCHITECTURE.md §13; SECURITY.md T-28; checklist R7)."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable
from pathlib import Path

import pytest

from git_reviewer.hook import install as hook
from git_reviewer.hook.install import CHAINED_NAME, HookError, install, script, status, uninstall
from tests.helpers import git

FOREIGN = b"#!/bin/sh\necho 'my own checks'\n"


@pytest.fixture(autouse=True)
def _own_git_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """The user's real global git configuration must not leak into these tests."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for name in ("XDG_CONFIG_HOME", "GIT_CONFIG_GLOBAL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    return home


@pytest.fixture
def binary(tmp_path: Path) -> Path:
    path = tmp_path / "tools" / "git-reviewer"
    path.parent.mkdir()
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def hooks_of(repo: Path) -> Path:
    return repo / ".git" / "hooks"


def foreign_hook(repo: Path, content: bytes = FOREIGN, mode: int = 0o755) -> Path:
    path = hooks_of(repo) / "pre-commit"
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(content)
    path.chmod(mode)
    return path


def test_install_writes_a_short_readable_executable_hook(
    make_repo: Callable[..., Path], binary: Path
) -> None:
    repo = make_repo()
    result = install(repo, binary, mode="block", chain=False)
    target = hooks_of(repo) / "pre-commit"
    assert result.path == target and result.chained is None
    assert stat.S_IMODE(target.stat().st_mode) == 0o755
    text = target.read_text(encoding="utf-8")
    assert text == script(binary, "block", None)
    lines = text.splitlines()
    assert lines[0] == "#!/bin/sh" and len(lines) <= 8
    assert lines[-1] == f"exec '{binary}' review --hook --mode block"
    assert "git commit --no-verify" in text and "git-reviewer uninstall-hook" in text
    assert status(repo) == ("ok", "installed (mode block)")


def test_warn_mode_is_written_in_the_hook(make_repo: Callable[..., Path], binary: Path) -> None:
    repo = make_repo()
    install(repo, binary, mode="warn", chain=False)
    text = (hooks_of(repo) / "pre-commit").read_text(encoding="utf-8")
    assert text.endswith("review --hook --mode warn\n")
    assert "security blocks still stop it" in text


def test_unknown_mode_is_refused(make_repo: Callable[..., Path], binary: Path) -> None:
    repo = make_repo()
    with pytest.raises(HookError, match="unknown mode"):
        install(repo, binary, mode="block; rm -rf ~", chain=False)  # type: ignore[arg-type]
    assert not (hooks_of(repo) / "pre-commit").exists()


def test_existing_hook_is_never_overwritten(make_repo: Callable[..., Path], binary: Path) -> None:
    repo = make_repo()
    existing = foreign_hook(repo)
    with pytest.raises(HookError, match=r"left untouched.*--chain"):
        install(repo, binary, mode="block", chain=False)
    assert existing.read_bytes() == FOREIGN
    assert stat.S_IMODE(existing.stat().st_mode) == 0o755
    assert not (hooks_of(repo) / CHAINED_NAME).exists()
    assert status(repo)[0] == "info" and "--chain" in status(repo)[1]


def test_chain_runs_the_existing_hook_first_and_uninstall_restores_it(
    make_repo: Callable[..., Path], binary: Path
) -> None:
    repo = make_repo()
    existing = foreign_hook(repo)
    result = install(repo, binary, mode="block", chain=True)
    chained = hooks_of(repo) / CHAINED_NAME
    assert result.chained == chained
    assert chained.read_bytes() == FOREIGN
    lines = existing.read_text(encoding="utf-8").splitlines()
    assert f"'{chained}' \"$@\" || exit $?" in lines
    assert lines.index(f"'{chained}' \"$@\" || exit $?") < len(lines) - 1  # before git-reviewer

    path, restored = uninstall(repo)
    assert path == existing and restored
    assert existing.read_bytes() == FOREIGN
    assert stat.S_IMODE(existing.stat().st_mode) == 0o755
    assert not chained.exists()


def test_chain_refuses_when_the_chained_name_is_taken(
    make_repo: Callable[..., Path], binary: Path
) -> None:
    repo = make_repo()
    existing = foreign_hook(repo)
    taken = hooks_of(repo) / CHAINED_NAME
    taken.write_bytes(b"older")
    with pytest.raises(HookError, match="parked"):
        install(repo, binary, mode="block", chain=True)
    assert existing.read_bytes() == FOREIGN and taken.read_bytes() == b"older"


def test_chain_refuses_a_hook_git_does_not_run(
    make_repo: Callable[..., Path], binary: Path
) -> None:
    # Not executable: git ignores it today; chaining would start running it.
    repo = make_repo()
    existing = foreign_hook(repo, mode=0o644)
    with pytest.raises(HookError, match="not executable"):
        install(repo, binary, mode="block", chain=True)
    assert existing.read_bytes() == FOREIGN
    assert not (hooks_of(repo) / CHAINED_NAME).exists()


def test_failed_write_puts_the_chained_hook_back(
    make_repo: Callable[..., Path], binary: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_repo()
    existing = foreign_hook(repo)

    def broken(target: Path, content: str, *, replace: bool) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(hook, "_write", broken)
    with pytest.raises(OSError, match="disk full"):
        install(repo, binary, mode="block", chain=True)
    assert existing.read_bytes() == FOREIGN
    assert not (hooks_of(repo) / CHAINED_NAME).exists()


@pytest.mark.parametrize("chain", [False, True])
def test_symlinked_hook_is_refused(
    make_repo: Callable[..., Path], binary: Path, tmp_path: Path, chain: bool
) -> None:
    repo = make_repo()
    shared = tmp_path / "shared-hook"
    shared.write_bytes(FOREIGN)
    hooks_of(repo).mkdir(exist_ok=True)
    (hooks_of(repo) / "pre-commit").symlink_to(shared)
    with pytest.raises(HookError, match="symbolic link"):
        install(repo, binary, mode="block", chain=chain)
    assert (hooks_of(repo) / "pre-commit").is_symlink()
    assert shared.read_bytes() == FOREIGN


def test_hook_that_is_a_directory_is_refused(make_repo: Callable[..., Path], binary: Path) -> None:
    repo = make_repo()
    (hooks_of(repo) / "pre-commit").mkdir(parents=True)
    with pytest.raises(HookError, match="not a regular file"):
        install(repo, binary, mode="block", chain=True)
    assert not (hooks_of(repo) / CHAINED_NAME).exists()


def test_symlinked_hooks_directory_is_refused(
    make_repo: Callable[..., Path], binary: Path, tmp_path: Path
) -> None:
    repo = make_repo()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    hooks = hooks_of(repo)
    if hooks.exists():
        for entry in hooks.iterdir():
            entry.unlink()
        hooks.rmdir()
    hooks.symlink_to(elsewhere)
    with pytest.raises(HookError, match="symbolic link or not a directory"):
        install(repo, binary, mode="block", chain=False)
    assert list(elsewhere.iterdir()) == []


def test_missing_hooks_directory_is_created(make_repo: Callable[..., Path], binary: Path) -> None:
    repo = make_repo()
    hooks = hooks_of(repo)
    for entry in hooks.iterdir():
        entry.unlink()
    hooks.rmdir()
    assert status(repo) == ("info", "not installed (git-reviewer install-hook)")
    assert not hooks.exists()  # status only reads
    install(repo, binary, mode="block", chain=False)
    assert stat.S_IMODE(hooks.stat().st_mode) == 0o755


def test_repository_hooks_path_is_refused(make_repo: Callable[..., Path], binary: Path) -> None:
    # husky, the pre-commit framework or a team setting: a hook in .git/hooks would never run.
    repo = make_repo()
    git(repo, "config", "core.hooksPath", ".husky")
    with pytest.raises(HookError, match=r"core\.hooksPath.*review --hook"):
        install(repo, binary, mode="block", chain=False)
    assert not (hooks_of(repo) / "pre-commit").exists()
    level, message = status(repo)
    assert level == "info" and "core.hooksPath" in message


def test_global_hooks_path_is_refused(
    make_repo: Callable[..., Path], binary: Path, _own_git_config: Path
) -> None:
    repo = make_repo()
    (_own_git_config / ".gitconfig").write_text(
        "[core]\n\thooksPath = ~/.githooks\n", encoding="utf-8"
    )
    with pytest.raises(HookError, match=r"core\.hooksPath"):
        install(repo, binary, mode="block", chain=False)
    assert not (hooks_of(repo) / "pre-commit").exists()


def test_xdg_hooks_path_is_refused(
    make_repo: Callable[..., Path],
    binary: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = make_repo()
    config = tmp_path / "xdg"
    (config / "git").mkdir(parents=True)
    (config / "git" / "config").write_text("[core]\n\thooksPath = /hooks\n", encoding="utf-8")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config))
    with pytest.raises(HookError, match=r"core\.hooksPath"):
        install(repo, binary, mode="block", chain=False)


def test_reinstall_switches_mode_and_keeps_the_chain(
    make_repo: Callable[..., Path], binary: Path
) -> None:
    repo = make_repo()
    foreign_hook(repo)
    install(repo, binary, mode="block", chain=True)
    result = install(repo, binary, mode="warn", chain=False)
    chained = hooks_of(repo) / CHAINED_NAME
    assert result.chained == chained
    text = (hooks_of(repo) / "pre-commit").read_text(encoding="utf-8")
    assert text == script(binary, "warn", chained)
    assert chained.read_bytes() == FOREIGN


def test_uninstall_refuses_what_it_did_not_install(
    make_repo: Callable[..., Path],
) -> None:
    repo = make_repo()
    with pytest.raises(HookError, match="nothing to remove"):
        uninstall(repo)
    existing = foreign_hook(repo)
    with pytest.raises(HookError, match="not installed by git-reviewer"):
        uninstall(repo)
    assert existing.read_bytes() == FOREIGN


def test_marker_must_be_on_the_second_line(make_repo: Callable[..., Path]) -> None:
    # A foreign hook that merely mentions git-reviewer is not ours: uninstall leaves it.
    repo = make_repo()
    foreign_hook(repo, b"#!/bin/sh\necho hi\n# Installed by git-reviewer: reviews\n")
    with pytest.raises(HookError, match="not installed by git-reviewer"):
        uninstall(repo)


def test_linked_worktree_installs_in_the_common_hooks_directory(
    make_repo: Callable[..., Path], binary: Path, tmp_path: Path
) -> None:
    repo = make_repo()
    linked = tmp_path / "linked"
    git(repo, "worktree", "add", "-q", "-b", "feature", str(linked))
    result = install(linked, binary, mode="block", chain=False)
    assert result.path == (repo / ".git" / "hooks" / "pre-commit").resolve()
    assert status(repo)[0] == "ok"


@pytest.mark.parametrize(
    ("make_binary", "reason"),
    [
        pytest.param(lambda repo, tmp: Path("git-reviewer"), "plain path", id="relative"),
        pytest.param(lambda repo, tmp: tmp / "it's" / "git-reviewer", "plain path", id="quote"),
        pytest.param(
            lambda repo, tmp: tmp / "new\nline" / "git-reviewer", "plain path", id="newline"
        ),
        pytest.param(
            lambda repo, tmp: repo / "bin" / "git-reviewer", "inside the rep", id="inside-repo"
        ),
        pytest.param(
            lambda repo, tmp: tmp / "via-link" / "git-reviewer",
            "inside the rep",
            id="link-into-repo",
        ),
        pytest.param(lambda repo, tmp: repo / "tool-link", "inside the rep", id="repo-link-out"),
    ],
)
def test_binary_the_hook_cannot_safely_run_is_refused(
    make_repo: Callable[..., Path],
    binary: Path,
    tmp_path: Path,
    make_binary: Callable[[Path, Path], Path],
    reason: str,
) -> None:
    repo = make_repo()
    (repo / "bin").mkdir()
    (repo / "bin" / "git-reviewer").write_text("#!/bin/sh\n", encoding="utf-8")
    (repo / "bin" / "git-reviewer").chmod(0o755)
    (tmp_path / "via-link").symlink_to(repo / "bin")
    # A link in the repository is content a commit could retarget, even if it points outside.
    (repo / "tool-link").symlink_to(binary)
    for name in ("it's", "new\nline"):
        (tmp_path / name).mkdir()
        target = tmp_path / name / "git-reviewer"
        target.write_text("#!/bin/sh\n", encoding="utf-8")
        target.chmod(0o755)
    with pytest.raises(HookError, match=reason):
        install(repo, make_binary(repo, tmp_path), mode="block", chain=False)
    assert not (hooks_of(repo) / "pre-commit").exists()


def test_non_executable_binary_is_refused(make_repo: Callable[..., Path], binary: Path) -> None:
    repo = make_repo()
    binary.chmod(0o644)
    with pytest.raises(HookError, match="not an executable file"):
        install(repo, binary, mode="block", chain=False)


def test_repository_path_that_cannot_be_quoted_is_refused(
    make_repo: Callable[..., Path], binary: Path, tmp_path: Path
) -> None:
    repo = make_repo()
    odd = tmp_path / "it's a repo"
    repo.rename(odd)
    with pytest.raises(HookError, match="shell script"):
        install(odd, binary, mode="block", chain=False)
    assert not (odd / ".git" / "hooks" / "pre-commit").exists()


def test_write_never_replaces_a_file_that_appeared(tmp_path: Path) -> None:
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    target = hooks / "pre-commit"
    target.write_bytes(FOREIGN)
    with pytest.raises(HookError, match="appeared meanwhile"):
        hook._write(target, "#!/bin/sh\n", replace=False)
    assert target.read_bytes() == FOREIGN
    assert [p.name for p in hooks.iterdir()] == ["pre-commit"]  # no temporary file left


def test_write_refuses_a_leftover_temporary_file(tmp_path: Path) -> None:
    target = tmp_path / "pre-commit"
    leftover = tmp_path / ".pre-commit.git-reviewer-new"
    leftover.symlink_to(tmp_path / "victim")
    with pytest.raises(HookError, match="already exists"):
        hook._write(target, "#!/bin/sh\n", replace=False)
    assert not target.exists() and not (tmp_path / "victim").exists()


# --- review findings: hooks git would not run, half-done states, hand edits ------------------


def test_empty_hooks_path_still_turns_git_hooks_off(
    make_repo: Callable[..., Path], binary: Path
) -> None:
    # `core.hooksPath =` is a common attempt to undo a global setting; git then ignores
    # .git/hooks, so a hook installed there would never run.
    repo = make_repo()
    git(repo, "config", "core.hooksPath", "")
    with pytest.raises(HookError, match=r"core\.hooksPath"):
        install(repo, binary, mode="block", chain=False)
    assert status(repo)[0] == "info"


def test_hooks_path_refusal_prints_the_exact_line_to_add(
    make_repo: Callable[..., Path], binary: Path
) -> None:
    repo = make_repo()
    git(repo, "config", "core.hooksPath", ".husky")
    with pytest.raises(HookError) as raised:
        install(repo, binary, mode="warn", chain=False)
    assert f"'{binary}' review --hook --mode warn" in str(raised.value)


def test_configuration_from_the_environment_is_refused(
    make_repo: Callable[..., Path], binary: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_repo()
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "/elsewhere")
    with pytest.raises(HookError, match="GIT_CONFIG_COUNT"):
        install(repo, binary, mode="block", chain=False)
    assert not (hooks_of(repo) / "pre-commit").exists()


def test_system_hooks_path_is_refused(
    make_repo: Callable[..., Path],
    binary: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = make_repo()
    system = tmp_path / "gitconfig"
    system.write_text("[core]\n\thooksPath = /etc/hooks\n", encoding="utf-8")
    monkeypatch.delenv("GIT_CONFIG_NOSYSTEM")
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(system))
    with pytest.raises(HookError, match=r"core\.hooksPath"):
        install(repo, binary, mode="block", chain=False)


def test_a_hook_changed_by_hand_is_never_replaced_or_removed(
    make_repo: Callable[..., Path], binary: Path
) -> None:
    repo = make_repo()
    install(repo, binary, mode="block", chain=False)
    target = hooks_of(repo) / "pre-commit"
    edited = target.read_text(encoding="utf-8").replace(
        "exec ", "./scripts/lint.sh || exit 1\nexec "
    )
    target.write_text(edited, encoding="utf-8")
    with pytest.raises(HookError, match="changed by hand"):
        install(repo, binary, mode="warn", chain=False)
    with pytest.raises(HookError, match="changed by hand"):
        uninstall(repo)
    assert target.read_text(encoding="utf-8") == edited
    assert status(repo) == ("info", "git-reviewer's hook, changed by hand")


def test_chain_keeps_the_original_file_itself(make_repo: Callable[..., Path], binary: Path) -> None:
    repo = make_repo()
    original = foreign_hook(repo)
    inode = original.stat().st_ino
    install(repo, binary, mode="block", chain=True)
    assert (hooks_of(repo) / CHAINED_NAME).stat().st_ino == inode


def test_chain_refuses_a_hook_that_reads_its_own_name(
    make_repo: Callable[..., Path], binary: Path
) -> None:
    # husky v4 and overcommit dispatch on basename "$0": renamed, they would silently do nothing.
    repo = make_repo()
    content = b'#!/bin/sh\nhookName=$(basename "$0")\nexec run-hooks "$hookName"\n'
    existing = foreign_hook(repo, content)
    with pytest.raises(HookError, match="own name"):
        install(repo, binary, mode="block", chain=True)
    assert existing.read_bytes() == content
    assert not (hooks_of(repo) / CHAINED_NAME).exists()


@pytest.mark.parametrize("hook_present", [False, True])
def test_a_parked_previous_hook_is_never_ignored(
    make_repo: Callable[..., Path], binary: Path, hook_present: bool
) -> None:
    # Left behind by an interrupted install or a hook deleted by hand: installing without it
    # would keep the user's hook switched off with no word.
    repo = make_repo()
    hooks_of(repo).mkdir(exist_ok=True)
    parked = hooks_of(repo) / CHAINED_NAME
    parked.write_bytes(FOREIGN)
    parked.chmod(0o755)
    if hook_present:
        foreign_hook(repo)
    with pytest.raises(HookError, match="parked"):
        install(repo, binary, mode="block", chain=True)
    assert parked.read_bytes() == FOREIGN
    if not hook_present:
        level, message = status(repo)
        assert level == "warn" and "mv " in message
        with pytest.raises(HookError, match="parked"):
            uninstall(repo)


def test_reinstall_refuses_a_chained_hook_that_became_a_symlink(
    make_repo: Callable[..., Path], binary: Path, tmp_path: Path
) -> None:
    repo = make_repo()
    foreign_hook(repo)
    install(repo, binary, mode="block", chain=True)
    chained = hooks_of(repo) / CHAINED_NAME
    shared = tmp_path / "shared"
    shared.write_bytes(FOREIGN)
    chained.unlink()
    chained.symlink_to(shared)
    before = (hooks_of(repo) / "pre-commit").read_bytes()
    with pytest.raises(HookError, match="symbolic link"):
        install(repo, binary, mode="warn", chain=False)
    with pytest.raises(HookError, match="nothing was changed"):
        uninstall(repo)
    assert (hooks_of(repo) / "pre-commit").read_bytes() == before
    assert chained.is_symlink()


def test_uninstall_works_even_when_hooks_path_is_set_later(
    make_repo: Callable[..., Path], binary: Path
) -> None:
    repo = make_repo()
    install(repo, binary, mode="block", chain=False)
    git(repo, "config", "core.hooksPath", ".husky")
    path, restored = uninstall(repo)
    assert not path.exists() and not restored


def test_status_warns_when_git_would_not_run_the_hook(
    make_repo: Callable[..., Path], binary: Path, tmp_path: Path
) -> None:
    repo = make_repo()
    foreign_hook(repo)
    install(repo, binary, mode="block", chain=True)
    target = hooks_of(repo) / "pre-commit"
    assert status(repo)[0] == "ok"

    target.chmod(0o644)
    assert status(repo)[0] == "warn" and "not executable" in status(repo)[1]
    target.chmod(0o755)

    (hooks_of(repo) / CHAINED_NAME).chmod(0o644)
    assert status(repo)[0] == "warn" and "previous hook" in status(repo)[1]
    (hooks_of(repo) / CHAINED_NAME).chmod(0o755)

    binary.unlink()
    assert status(repo)[0] == "warn" and "missing or not executable" in status(repo)[1]


def test_status_warns_after_the_repository_moved(
    make_repo: Callable[..., Path], binary: Path, tmp_path: Path
) -> None:
    # The script names the previous hook by its old absolute path: commits would fail.
    repo = make_repo()
    foreign_hook(repo)
    install(repo, binary, mode="block", chain=True)
    moved = tmp_path / "moved"
    repo.rename(moved)
    level, message = status(moved)
    assert level == "warn" and "moved" in message
    result = install(moved, binary, mode="block", chain=False)
    assert result.chained == (moved / ".git" / "hooks" / CHAINED_NAME).resolve()
    assert status(moved)[0] == "ok"


def test_umask_that_leaves_the_hook_not_executable_is_refused(
    make_repo: Callable[..., Path], binary: Path
) -> None:
    repo = make_repo()
    previous = os.umask(0o177)
    try:
        with pytest.raises(HookError, match="umask"):
            install(repo, binary, mode="block", chain=False)
    finally:
        os.umask(previous)
    assert not (hooks_of(repo) / "pre-commit").exists()
    assert [p.name for p in hooks_of(repo).iterdir() if "git-reviewer" in p.name] == []


def test_binary_writable_by_others_is_refused(make_repo: Callable[..., Path], binary: Path) -> None:
    repo = make_repo()
    binary.parent.chmod(0o777)
    try:
        with pytest.raises(HookError, match="writable by group or others"):
            install(repo, binary, mode="block", chain=False)
    finally:
        binary.parent.chmod(0o755)


def test_binary_inside_the_repository_is_found_whatever_the_case(
    make_repo: Callable[..., Path],
) -> None:
    # macOS file systems ignore case: a path typed in another case is the same file.
    repo = make_repo()
    swapped = Path(str(repo).swapcase())
    if not swapped.exists():
        pytest.skip("case-sensitive file system")
    inside = repo / "bin" / "git-reviewer"
    inside.parent.mkdir()
    inside.write_text("#!/bin/sh\n", encoding="utf-8")
    inside.chmod(0o755)
    with pytest.raises(HookError, match="inside the repository"):
        install(repo, swapped / "bin" / "git-reviewer", mode="block", chain=False)
