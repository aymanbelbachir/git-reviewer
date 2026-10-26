"""Install, chain and remove the pre-commit hook (effect module; docs/SPEC.md security
requirement 7; docs/ARCHITECTURE.md §13; SECURITY.md T-28).

- An existing hook is never overwritten: installing refuses, or with `chain` keeps it as
  `pre-commit.chained-by-git-reviewer` and runs it first; uninstalling puts it back.
- The hook goes in the common git directory's `hooks/` (shared by linked worktrees). When git is
  told to look elsewhere (`core.hooksPath`, set by husky, the pre-commit framework or a team
  setting), a hook in `.git/hooks` would silently never run: installing refuses and prints the line
  to add to that hook manager instead. A symlinked hook or hooks directory is refused too.
- The script is a few readable lines that run git-reviewer by its absolute path. git-reviewer only
  replaces or removes a hook that is exactly what it wrote; one changed by hand is left alone.
The hook is a convenience, not a security boundary: `git commit --no-verify` skips it.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from git_reviewer import proc
from git_reviewer.git.command import run_git, stderr_text

HOOK_NAME = "pre-commit"
CHAINED_NAME = "pre-commit.chained-by-git-reviewer"
MARKER = "# Installed by git-reviewer"
_UNSAFE_PATH_CHARS = frozenset("'\n\r\x00")
_READ_LIMIT = 64 * 1024
_MAX_LINK_HOPS = 40
# Configuration git can also take from the environment; the lookup below cannot be given it
# (proc passes variables by exact name only).
_ENV_CONFIG = ("GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS")
_USER_CONFIG_ENV = (
    "XDG_CONFIG_HOME",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_NOSYSTEM",
)
_EXEC_LINE = re.compile(r"exec '([^'\n]*)' review --hook --mode (block|warn)")
_CHAIN_LINE = re.compile(r"'([^'\n]*)' \"\$@\" \|\| exit \$\?")
# A hook that reads its own name (husky v4, overcommit) would stop working once renamed.
_READS_OWN_NAME = re.compile(rb"\$\{?0\b")

Mode = Literal["block", "warn"]
Level = Literal["ok", "info", "warn"]
Kind = Literal["absent", "special", "foreign", "edited", "ours"]


class HookError(RuntimeError):
    """The hook was not installed or removed; nothing was changed."""


@dataclass(frozen=True)
class HookResult:
    path: Path
    chained: Path | None


@dataclass(frozen=True)
class _Ours:
    """A hook exactly as git-reviewer writes it."""

    binary: Path
    mode: Mode
    chained: Path | None


def script(binary: Path, mode: Mode, chained: Path | None) -> str:
    """The hook script: short enough to read before trusting it."""
    effect = (
        "a finding at or above the threshold stops the commit"
        if mode == "block"
        else "findings are reported, the commit goes on (security blocks still stop it)"
    )
    lines = [
        "#!/bin/sh",
        f"{MARKER}: reviews the staged changes before each commit.",
        f"# Mode: {mode} ({effect}).",
        "# Skip once: git commit --no-verify",
        "# Remove:    git-reviewer uninstall-hook",
    ]
    if chained is not None:
        lines.append("# Your previous pre-commit hook runs first; the commit stops if it fails.")
        lines.append(f'{_quoted(chained)} "$@" || exit $?')
    lines.append(f"exec {_quoted(binary)} review --hook --mode {mode}")
    return "\n".join(lines) + "\n"


def install(repo: Path, binary: Path, *, mode: Mode, chain: bool) -> HookResult:
    if mode not in ("block", "warn"):
        raise HookError(f"unknown mode {mode!r}")
    _check_binary(repo, binary)
    manual = f"add this line to the pre-commit hook yourself: {_command(binary, mode)}"
    elsewhere = _hooks_elsewhere(repo)
    if elsewhere is not None:
        raise HookError(f"{elsewhere}. Nothing was installed; {manual}")
    hooks = _hooks_dir(repo, create=True)
    if _UNSAFE_PATH_CHARS & set(str(hooks)):
        raise HookError(f"cannot write {hooks!r} into a shell script")
    target, chained = hooks / HOOK_NAME, hooks / CHAINED_NAME
    kind, ours = _inspect(target)
    previous = _inspect(chained)[0]
    if kind == "edited":
        raise HookError(
            f"{target} is git-reviewer's hook changed by hand: it is left untouched. Move your "
            "changes to another hook, delete it, and install again"
        )
    if kind == "special":
        raise HookError(
            f"{target} is a symbolic link or not a regular file: it is left untouched; {manual}"
        )
    if ours is not None:
        # Re-installing (e.g. another mode) keeps a chain set up earlier, at its current path.
        if ours.chained is None:
            if previous != "absent":
                raise HookError(_parked(chained, None))
            _write(target, script(binary, mode, None), replace=True)
            return HookResult(target, None)
        _check_chainable(chained)
        _write(target, script(binary, mode, chained), replace=True)
        return HookResult(target, chained)
    if previous != "absent":
        raise HookError(_parked(chained, target if kind == "absent" else None))
    if kind == "absent":
        _write(target, script(binary, mode, None), replace=False)
        return HookResult(target, None)
    if not chain:
        raise HookError(
            f"{target} already exists and is not git-reviewer's: it is left untouched. Rerun "
            f"with --chain to run it first, or {manual}"
        )
    _check_chainable(target)
    if _reads_own_name(target):
        raise HookError(
            f"{target} reads its own name ($0), so it would not work renamed: it "
            f"is left untouched; {manual}"
        )
    # The original keeps its inode under the new name (a link fails if the name exists), then
    # the new hook is swapped in by rename: there is never a moment without a pre-commit hook.
    try:
        os.link(target, chained, follow_symlinks=False)
    except FileExistsError as exc:
        raise HookError(f"{chained} appeared meanwhile: nothing was changed") from exc
    try:
        _write(target, script(binary, mode, chained), replace=True)
    except BaseException:
        chained.unlink(missing_ok=True)  # the original is still in place
        raise
    return HookResult(target, chained)


def uninstall(repo: Path) -> tuple[Path, bool]:
    """Remove our hook and restore a chained one. Returns (hook path, restored). Works whatever
    core.hooksPath says: removing our own file from `.git/hooks` is always safe."""
    hooks = _hooks_dir(repo, create=False)
    target, chained = hooks / HOOK_NAME, hooks / CHAINED_NAME
    kind = _inspect(target)[0]
    previous = _inspect(chained)[0]
    if kind == "absent":
        hint = f" ({_parked(chained, target)})" if previous != "absent" else ""
        raise HookError(f"no pre-commit hook in {hooks}: nothing to remove{hint}")
    if kind == "edited":
        raise HookError(
            f"{target} is git-reviewer's hook changed by hand: it is left untouched; "
            "delete it yourself"
        )
    if kind != "ours":
        raise HookError(f"{target} was not installed by git-reviewer: it is left untouched")
    if previous == "absent":
        target.unlink()
        return target, False
    if previous == "special":
        raise HookError(
            f"{chained} is a symbolic link or not a regular file: nothing was changed; put "
            f"your previous hook back as {target} by hand"
        )
    chained.rename(target)  # one step: the previous hook replaces git-reviewer's
    return target, True


def status(repo: Path) -> tuple[Level, str]:
    """Whether git really runs git-reviewer before each commit, for `doctor`. Read-only."""
    elsewhere = _hooks_elsewhere(repo)
    if elsewhere is not None:
        return "info", elsewhere
    hooks = _hooks_dir(repo, create=False)
    target, chained = hooks / HOOK_NAME, hooks / CHAINED_NAME
    kind, ours = _inspect(target)
    previous = _inspect(chained)[0]
    if kind == "absent":
        if previous != "absent":
            return "warn", f"not installed; {_parked(chained, target)}"
        return "info", "not installed (git-reviewer install-hook)"
    if kind == "special":
        return "warn", f"{target} is a symbolic link or not a regular file"
    if kind == "foreign":
        return "info", "another pre-commit hook is installed (git-reviewer install-hook --chain)"
    if ours is None:
        return "info", "git-reviewer's hook, changed by hand"
    problem = _problem(target, ours, chained, previous)
    if problem is not None:
        return "warn", f"installed, but {problem}: run git-reviewer install-hook again"
    return "ok", f"installed (mode {ours.mode})"


def _problem(target: Path, ours: _Ours, chained: Path, previous: Kind) -> str | None:
    """Why git would not run our hook as installed, if it would not."""
    if not os.access(target, os.X_OK):
        return f"{target} is not executable, so git skips it"
    if not ours.binary.is_file() or not os.access(ours.binary, os.X_OK):
        return f"it runs {ours.binary}, which is missing or not executable"
    if ours.chained is None:
        return f"a previous hook is parked at {chained}" if previous != "absent" else None
    if ours.chained != chained or previous == "special" or not os.access(chained, os.X_OK):
        # e.g. the repository was moved: the script names the previous hook's old path.
        return "the previous hook it runs first is missing, moved or not executable"
    return None


def _hooks_elsewhere(repo: Path) -> str | None:
    """Why git would not run `.git/hooks`, or None when it does."""
    from_env = [name for name in _ENV_CONFIG if name in os.environ]
    if from_env:
        return (
            f"git takes configuration from the environment ({', '.join(from_env)}), so "
            "git-reviewer cannot tell where git looks for hooks"
        )
    configured = _configured_hooks_path(repo)
    if configured is None:
        return None
    return (
        f"git runs hooks from {configured!r} (core.hooksPath, e.g. husky or the pre-commit "
        "framework), not from .git/hooks"
    )


def _configured_hooks_path(repo: Path) -> str | None:
    """core.hooksPath as git really sees it (system, global and repository configuration), or
    None when not set: even an empty value turns `.git/hooks` off. The hardened run_git ignores
    global configuration and overrides core.hooksPath, so this one call uses git's normal view,
    read-only (`git config --get` runs nothing)."""
    try:
        home = str(Path.home())
    except RuntimeError as exc:
        raise HookError("cannot find your home directory to read your git configuration") from exc
    env = {"HOME": home}
    for name in _USER_CONFIG_ENV:
        if os.environ.get(name):
            env[name] = os.environ[name]
    result = proc.run(
        "git",
        ["config", "--get", "core.hooksPath"],
        cwd=repo,
        env_extra=env,
        forbidden_root=repo,
    )
    if result.returncode == 1:  # not set
        return None
    if result.returncode != 0:
        raise HookError(f"cannot read the git configuration: {stderr_text(result)}")
    return result.stdout.decode("utf-8", "replace").strip()


def _hooks_dir(repo: Path, *, create: bool) -> Path:
    result = run_git(repo, ["rev-parse", "--path-format=absolute", "--git-common-dir"])
    if result.returncode != 0:
        raise HookError(f"cannot find the git directory: {stderr_text(result)}")
    try:
        hooks = Path(result.stdout.decode("utf-8", "strict").strip()) / "hooks"
    except UnicodeDecodeError as exc:
        raise HookError("the path of the git directory is not valid UTF-8") from exc
    try:
        info = hooks.lstat()
    except FileNotFoundError:
        if create:
            hooks.mkdir(mode=0o755)
        return hooks
    if not stat.S_ISDIR(info.st_mode):
        raise HookError(f"{hooks} is a symbolic link or not a directory")
    return hooks


def _inspect(path: Path) -> tuple[Kind, _Ours | None]:
    """'special' is a symlink (lstat does not follow it) or anything but a regular file; 'edited'
    carries our marker but is not exactly what git-reviewer writes."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return "absent", None
    if not stat.S_ISREG(info.st_mode):
        return "special", None
    head = _head(path)
    lines = head.splitlines()
    if len(lines) < 2 or not lines[1].startswith(MARKER.encode()):
        return "foreign", None
    ours = _parse(head)
    return ("ours", ours) if ours is not None else ("edited", None)


def _head(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        return handle.read(_READ_LIMIT)


def _parse(content: bytes) -> _Ours | None:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return None
    lines = text.splitlines()
    found = _EXEC_LINE.fullmatch(lines[-1]) if lines else None
    if found is None:
        return None
    chain = next((match for line in lines if (match := _CHAIN_LINE.fullmatch(line))), None)
    mode: Mode = "block" if found[2] == "block" else "warn"
    ours = _Ours(Path(found[1]), mode, Path(chain[1]) if chain else None)
    return ours if text == script(ours.binary, ours.mode, ours.chained) else None


def _check_chainable(path: Path) -> None:
    if _inspect(path)[0] == "special":
        raise HookError(f"{path} is a symbolic link or not a regular file: nothing was changed")
    if not os.access(path, os.X_OK):
        # git never runs it; chaining it would start running it (or fail every commit).
        raise HookError(f"{path} is not executable, so git ignores it: remove it first")


def _reads_own_name(path: Path) -> bool:
    return _READS_OWN_NAME.search(_head(path)) is not None


def _parked(chained: Path, target: Path | None) -> str:
    restore = f": put it back with: mv '{chained}' '{target}'" if target is not None else ""
    return f"a previous hook is parked at {chained}{restore}"


def _write(target: Path, content: str, *, replace: bool) -> None:
    """Create the hook. Without `replace`, never replaces an existing file: the new file is
    hard-linked into place, which fails if the name exists."""
    temporary = target.with_name(f".{target.name}.git-reviewer-new")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        # Mode 0755 less the umask, like any file the user creates.
        descriptor = os.open(temporary, flags, 0o755)
    except FileExistsError as exc:
        raise HookError(f"{temporary} already exists: remove it and retry") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            if stat.S_IMODE(os.fstat(handle.fileno()).st_mode) & 0o500 != 0o500:
                raise HookError("your umask removes the read or execute permission git needs")
            handle.write(content)
        if replace:
            temporary.replace(target)
        else:
            try:
                os.link(temporary, target, follow_symlinks=False)
            except FileExistsError as exc:
                raise HookError(f"{target} appeared meanwhile: it is left untouched") from exc
    finally:
        temporary.unlink(missing_ok=True)


def _check_binary(repo: Path, binary: Path) -> None:
    if not binary.is_absolute() or _UNSAFE_PATH_CHARS & set(str(binary)):
        raise HookError(f"cannot use {binary!r} in the hook: run git-reviewer by a plain path")
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise HookError(
            f"{binary} is not an executable file: run install-hook with the installed "
            "git-reviewer command"
        )
    # The repository's content is untrusted: the hook must never run a binary from it (any of
    # its worktrees: the hook serves them all), nor through a symbolic link a commit could
    # retarget, at any hop of a chain of links. Compared by file identity, not by name: macOS
    # file systems ignore case and Unicode normalization.
    hops = _link_chain(binary)
    for root in (repo, *_worktrees(repo)):
        if any(_inside(hop, root) for hop in hops):
            raise HookError(
                f"{binary} is inside the repository or one of its worktrees, or reaches it "
                "through a symbolic link: install git-reviewer outside it (for example with uv "
                "tool install) before installing the hook"
            )
    try:
        # The folder holding each link (e.g. ~/.local/bin) and the program they lead to.
        for hop in hops:
            proc.check_not_writable_by_others(hop)
    except proc.UnsafeBinaryError as exc:
        raise HookError(f"{exc}: another user could change what the hook runs") from exc


def _link_chain(binary: Path) -> list[Path]:
    """The path given, where every symbolic link on the way physically lives, and the resolved
    program. "Physically": a link reached through a folder that is itself a symlink (~/bin to a
    folder of a repository) lives in that repository, whatever the path says."""
    hops = [binary]
    current = _physical(binary)
    for _ in range(_MAX_LINK_HOPS):
        hops.append(current)
        if not current.is_symlink():
            return [*hops, binary.resolve()]
        target = current.readlink()
        # The system reads a relative target from the link's real folder: so does this.
        current = _physical(target if target.is_absolute() else current.parent / target)
    raise HookError(f"{binary} goes through too many symbolic links")


def _physical(path: Path) -> Path:
    """`path` with its folder resolved, but not the last component (which may be a link)."""
    try:
        return path.parent.resolve(strict=True) / path.name
    except OSError as exc:
        raise HookError(f"cannot resolve the folder of {path}: {exc.strerror}") from exc


def _worktrees(repo: Path) -> list[Path]:
    result = run_git(repo, ["worktree", "list", "--porcelain", "-z"])
    if result.returncode != 0:
        raise HookError(f"cannot list the worktrees: {stderr_text(result)}")
    found: list[Path] = []
    for field in result.stdout.split(b"\0"):
        if field.startswith(b"worktree "):
            try:
                found.append(Path(field[len(b"worktree ") :].decode("utf-8", "strict")))
            except UnicodeDecodeError as exc:
                raise HookError("a worktree path is not valid UTF-8") from exc
    return found


def _inside(path: Path, root: Path) -> bool:
    """Whether `path` is `root` or below it. What cannot be checked is refused, never skipped:
    a worktree that git lists but that is missing may have been moved by hand and still be used."""
    try:
        root_info = root.stat()
        for parent in (path, *path.parents):
            if os.path.samestat(parent.stat(), root_info):
                return True
    except FileNotFoundError as exc:
        raise HookError(
            f"{exc.filename} is missing: if it is a worktree that was moved or deleted, run "
            "git worktree repair or git worktree prune, then retry"
        ) from exc
    except OSError as exc:
        raise HookError(f"cannot check whether {path} is inside {root}: {exc.strerror}") from exc
    return False


def _command(binary: Path, mode: Mode) -> str:
    return f"{_quoted(binary)} review --hook --mode {mode}"


def _quoted(path: Path) -> str:
    return f"'{path}'"
