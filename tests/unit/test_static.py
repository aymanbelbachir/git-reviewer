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


QUERY_BEFORE = (
    "def find(cursor, name):\n"
    "    query = (\n"
    '        "SELECT * FROM users "\n'
    "        \"WHERE name = 'admin'\"\n"
    "    )\n"
    "    return cursor.execute(query)\n"
)


def test_finding_reported_on_an_unchanged_line_of_a_changed_statement(
    make_repo: Callable[..., Path],
) -> None:
    # bandit reports the query on line 3 (range 3-4); only line 4, `% name`, is added.
    repo = make_repo({"db.py": QUERY_BEFORE})
    after = QUERY_BEFORE.replace("'admin'\"\n", '%s" % name\n')
    write_files(repo, {"db.py": after})
    git(repo, "add", "-A")
    assert ("bandit", "B608", "db.py", 4) in rules(repo)


def test_changed_argument_of_a_multi_line_call_reports_the_call(
    make_repo: Callable[..., Path],
) -> None:
    before = (
        "import subprocess\n\n\ndef run(name):\n    return subprocess.run(\n"
        '        "ls",\n        shell=True,\n    )\n'
    )
    repo = make_repo({"app.py": before})
    write_files(repo, {"app.py": before.replace('"ls"', '"ls " + name')})
    git(repo, "add", "-A")
    found = rules(repo)
    assert ("bandit", "B602", "app.py", 6) in found


def test_statement_untouched_by_the_change_is_still_not_reported(
    make_repo: Callable[..., Path],
) -> None:
    repo = make_repo({"db.py": QUERY_BEFORE.replace("'admin'\"", '%s" % name')})
    write_files(repo, {"db.py": QUERY_BEFORE.replace("'admin'\"", '%s" % name') + "X = 1\n"})
    git(repo, "add", "-A")
    assert not any(rule == "B608" for _, rule, _, _ in rules(repo))


def test_new_key_in_an_old_dict_does_not_bring_back_its_findings(
    make_repo: Callable[..., Path],
) -> None:
    # bandit's B104 and B108 report the whole dict as their range: only their own line counts.
    before = (
        'SETTINGS = {\n    "host": "0.0.0.0",\n    "cache": "/tmp/app-cache",\n    "port": 80,\n}\n'
    )
    repo = make_repo({"settings.py": before})
    write_files(
        repo, {"settings.py": before.replace('"port": 80,\n', '"port": 80,\n    "retries": 3,\n')}
    )
    git(repo, "add", "-A")
    assert not any(rule in {"B104", "B108"} for _, rule, _, _ in rules(repo))


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


def test_a_patch_must_not_add_a_serious_scanner_finding(tmp_path: Path) -> None:
    # The scanners on both versions of the one file: only what the patch adds counts.
    from git_reviewer.static.analyze import added_findings

    before = "import yaml\n\n\ndef load(raw):\n    return yaml.safe_load(raw)\n"
    worse = before.replace("yaml.safe_load(raw)", "yaml.load(raw, Loader=yaml.Loader)")
    assert added_findings("app.py", before, worse, tmp_path) == [
        "adds a bandit finding (B506) on line 5"
    ]
    assert added_findings("app.py", worse, before, tmp_path) == []


def test_a_risky_call_moved_into_a_new_helper_is_refused(tmp_path: Path) -> None:
    # Same number of eval calls, but the eval sits on a line the patch adds.
    from git_reviewer.static.analyze import added_findings

    before = "def parse(value):\n    return eval(value)\n"
    after = (
        "import ast\n\n\ndef _legacy(value):\n    return eval(value)\n\n\n"
        "def parse(value):\n    try:\n        return ast.literal_eval(value)\n"
        "    except ValueError:\n        return _legacy(value)\n"
    )
    assert any("B307" in reason for reason in added_findings("app.py", before, after, tmp_path))


def test_a_hardcoded_password_is_refused_although_bandit_rates_it_low(tmp_path: Path) -> None:
    from git_reviewer.static.analyze import added_findings

    before = "def check(password):\n    return password == load()\n"
    after = "def check(password):\n    return password == 'letmein-debug' or password == load()\n"
    assert any("B105" in reason for reason in added_findings("app.py", before, after, tmp_path))


def test_an_original_the_scanners_cannot_parse_counts_as_empty(tmp_path: Path) -> None:
    from git_reviewer.static.analyze import added_findings

    assert (
        added_findings("app.py", "def broken(:\n", "def fixed():\n    return 1\n", tmp_path) == []
    )
