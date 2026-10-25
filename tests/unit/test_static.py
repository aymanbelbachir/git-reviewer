from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from git_reviewer.git.diff import DiffLimits, collect_staged
from git_reviewer.git.snapshot import SnapshotError, reviewed_files
from git_reviewer.static.analyze import run_static_analysis
from tests.helpers import git, random_token, write_files

LIMITS = DiffLimits(max_bytes=1024 * 1024, max_files=200, max_line_chars=10_000)


def rules(repo: Path) -> set[tuple[str, str, str, int]]:
    result = run_static_analysis(repo, collect_staged(repo, LIMITS))
    return {(f.tool, f.rule, f.file, f.line) for f in result.findings}


def test_scanners_report_on_added_lines(make_repo: Callable[..., Path]) -> None:
    repo = make_repo()
    code = (
        "import subprocess\n\n\ndef run(arg):\n"
        "    subprocess.call(arg, shell=True)\n    return missing\n"
    )
    write_files(repo, {"app.py": code})
    git(repo, "add", "-A")
    found = rules(repo)
    assert ("bandit", "B602", "app.py", 5) in found
    assert ("ruff", "F821", "app.py", 6) in found


def test_preexisting_issues_are_not_reported(make_repo: Callable[..., Path]) -> None:
    repo = make_repo({"app.py": "import os\nx = undefined\n"})
    write_files(repo, {"app.py": "import os\nx = undefined\ny = 1\n"})
    git(repo, "add", "-A")
    assert all(line == 3 for _, _, _, line in rules(repo))


def test_reviewed_content_is_the_staged_content(make_repo: Callable[..., Path]) -> None:
    repo = make_repo()
    write_files(repo, {"app.py": "x = undefined_name\n"})
    git(repo, "add", "-A")
    write_files(repo, {"app.py": "x = 1\n"})  # clean working tree, dirty index
    assert ("ruff", "F821", "app.py", 1) in rules(repo)


def test_secret_values_never_appear_in_findings(make_repo: Callable[..., Path]) -> None:
    token = random_token()
    repo = make_repo()
    write_files(repo, {"settings.py": f'TOKEN = "{token}"\n'})
    git(repo, "add", "-A")
    result = run_static_analysis(repo, collect_staged(repo, LIMITS))
    leaks = [f for f in result.findings if f.tool == "gitleaks"]
    assert leaks and leaks[0].severity == "critical"
    assert token in result.secrets
    assert all(token not in f.message for f in result.findings)


def test_symlinks_are_not_exported(make_repo: Callable[..., Path]) -> None:
    repo = make_repo()
    (repo / "link.py").symlink_to("/etc/hosts")
    write_files(repo, {"real.py": "x = 1\n"})
    git(repo, "add", "-A")
    with reviewed_files(repo, collect_staged(repo, LIMITS)) as snapshot:
        assert snapshot.files == ("real.py",)
        assert not (snapshot.root / "link.py").exists()
        assert oct(snapshot.root.stat().st_mode & 0o777) == "0o700"
        assert oct((snapshot.root / "real.py").stat().st_mode & 0o777) == "0o600"


def test_snapshot_is_removed_afterwards(make_repo: Callable[..., Path]) -> None:
    repo = make_repo()
    write_files(repo, {"a.py": "x = 1\n"})
    git(repo, "add", "-A")
    with reviewed_files(repo, collect_staged(repo, LIMITS)) as snapshot:
        root = snapshot.root
    assert not root.exists()


def test_case_collisions_fail_closed(make_repo: Callable[..., Path], tmp_path: Path) -> None:
    probe = tmp_path / "case-probe"
    probe.touch()
    if not (tmp_path / "CASE-PROBE").exists():
        pytest.skip("needs a case-insensitive file system (macOS default)")
    repo = make_repo()
    blob = git(repo, "hash-object", "-w", "--stdin").stdout.decode().strip()
    git(repo, "update-index", "--add", "--cacheinfo", f"100644,{blob},A.py")
    git(repo, "update-index", "--add", "--cacheinfo", f"100644,{blob},a.py")
    with pytest.raises(SnapshotError), reviewed_files(repo, collect_staged(repo, LIMITS)):
        pass


def test_file_bandit_cannot_parse_means_not_fully_analyzed(make_repo: Callable[..., Path]) -> None:
    repo = make_repo()
    write_files(repo, {"broken.py": "x = 1\ndef broken(:\n    pass\n"})
    git(repo, "add", "-A")
    result = run_static_analysis(repo, collect_staged(repo, LIMITS))
    assert result.incomplete == ("bandit could not parse 1 Python file(s)",)
    assert result.notes == ("bandit could not analyze broken.py",)
    assert ("bandit", 0) in result.coverage


def test_gitleaksignore_is_not_exported(make_repo: Callable[..., Path]) -> None:
    repo = make_repo()
    write_files(repo, {".gitleaksignore": "a.py:generic-api-key:1\n", "a.py": "x = 1\n"})
    git(repo, "add", "-A")
    with reviewed_files(repo, collect_staged(repo, LIMITS)) as snapshot:
        assert snapshot.files == ("a.py",)


@pytest.mark.parametrize("tool", ["ruff", "bandit", "gitleaks"])
def test_empty_scanner_output_fails_closed(
    make_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    from git_reviewer import proc
    from git_reviewer.static import tools
    from git_reviewer.static.tools import StaticAnalysisError

    real_run = proc.run

    def silent(program: str, *args: object, **kwargs: object) -> proc.Result:
        result = real_run(program, *args, **kwargs)  # type: ignore[arg-type]
        if program != tool:
            return result
        if tool == "gitleaks":  # the report goes to a file
            (Path(str(kwargs["cwd"])) / "gitleaks.json").write_bytes(b"")
        return proc.Result(returncode=result.returncode, stdout=b"", stderr=b"")

    repo = make_repo()
    write_files(repo, {"a.py": "x = 1\n"})
    git(repo, "add", "-A")
    monkeypatch.setattr(tools.proc, "run", silent)
    with pytest.raises(StaticAnalysisError):
        run_static_analysis(repo, collect_staged(repo, LIMITS))


def test_scanner_line_beyond_gits_last_line_blocks(make_repo: Callable[..., Path]) -> None:
    repo = make_repo()
    write_files(repo, {"a.py": "x = 1  # note\rimport os\n"})
    git(repo, "add", "-A")
    result = run_static_analysis(repo, collect_staged(repo, LIMITS))
    assert [d.source for d in result.blocks] == ["static.integrity"]


def test_unmappable_scanner_result_fails_closed(
    make_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    from git_reviewer.static import tools
    from git_reviewer.static.tools import StaticAnalysisError

    repo = make_repo()
    write_files(repo, {"a.py": "x = undefined_name\n"})
    git(repo, "add", "-A")
    monkeypatch.setattr(tools, "_relative", lambda value, snapshot: None)
    with pytest.raises(StaticAnalysisError, match="cannot be mapped"):
        run_static_analysis(repo, collect_staged(repo, LIMITS))
