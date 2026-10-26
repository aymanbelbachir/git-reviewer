from __future__ import annotations

import pytest

from git_reviewer.patch.checks import problems

APP = """import subprocess


def run(name):
    return subprocess.run(["ls", name], check=True)
"""

TEST = """import pytest

from app import add


def test_add():
    assert add(2, 3) == 5


def test_add_negative():
    assert add(-1, 1) == 0
"""


def test_a_clean_fix_passes() -> None:
    fixed = APP.replace('["ls", name]', '["ls", "--", name]')
    assert problems("app.py", APP, fixed) == []


def test_a_stdlib_import_is_allowed() -> None:
    fixed = "import shlex\n" + APP
    assert problems("app.py", APP, fixed) == []


@pytest.mark.parametrize(
    ("addition", "message"),
    [
        ("import socket\n", "import of socket"),
        ("import urllib.request\n", "import of urllib"),
        ("from ctypes import CDLL\n", "import of ctypes"),
        ("import requests\n", "not in the standard library"),
        ("x = eval('1')\n", "use of eval"),
        ("exec('print(1)')\n", "use of exec"),
        ("__import__('os').system('id')\n", "use of __import__"),
        ("import os\nos.system('id')\n", "use of os.system"),
        ("import os\nos.execv('/bin/sh', ['sh'])\n", "use of os.execv"),
        ("subprocess.Popen('id', shell=True)\n", "use of subprocess.Popen"),
        ("import base64\nbase64.b64decode('aWQ=')\n", "use of base64.b64decode"),
        ("x = getattr(subprocess, 'run' + 'x')\n", "getattr with a computed name"),
        ("y = chr(105) + chr(100)\n", "use of chr"),
        (f"BLOB = '{'A' * 300}'\n", "string literal longer"),
        (f"Z = 'a{chr(0x200B)}b'\n", "invisible or control characters"),
        ("try:\n    pass\nexcept Exception:\n    pass\n", "catches everything"),
        ("from os import system\nsystem('id')\n", "use of os.system"),
        ("import os as o\no.system('id')\n", "use of os.system"),
        ("from subprocess import Popen\nPopen('id')\n", "use of subprocess.Popen"),
        ("run_it = eval\n", "use of eval"),
        ("import builtins\nbuiltins.exec('1')\n", "import of builtins"),
        ("from os import *\nsystem('id')\n", "star import"),
        ("import os\nos._exit(0)\n", "use of os._exit"),
        ("import os\ngetattr(os, 'sys' 'tem')('id')\n", "use of os.system"),
        ("import os\nos.posix_spawn('/bin/sh', ['sh'], {})\n", "use of os.posix_spawn"),
        ("try:\n    pass\nexcept (ValueError, Exception):\n    pass\n", "catches everything"),
        ("try:\n    pass\nexcept:\n    pass\n", "catches everything"),
    ],
)
def test_risky_additions_are_refused(addition: str, message: str) -> None:
    found = problems("app.py", APP, APP + addition)
    assert any(message in problem for problem in found), found


def test_existing_risky_code_is_not_held_against_the_patch() -> None:
    original = APP + "import socket\nx = eval('1')\n"
    fixed = original.replace('["ls", name]', '["ls", "--", name]')
    assert problems("app.py", original, fixed) == []


def test_invalid_python_is_refused() -> None:
    expected = ["the patched file is not valid Python"]
    assert problems("app.py", APP, APP + "def broken(:\n") == expected


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda t: t.replace("    assert add(-1, 1) == 0\n", "    pass\n"), "assertion"),
        (lambda t: t.replace("== 5", "== 6"), "assertion"),
        (lambda t: t.replace("def test_add_negative", "def check_add_negative"), "test"),
        (lambda t: t.replace("def test_add():", "@pytest.mark.skip\ndef test_add():"), "skip"),
        (lambda t: t.replace("def test_add():", "@pytest.mark.xfail\ndef test_add():"), "xfail"),
        (lambda t: t.replace("    assert add(2, 3) == 5", "    pytest.skip()"), "skip"),
        (lambda t: t.replace("def test_add():\n", "def test_add():\n    return\n"), "early return"),
        (
            lambda t: t.replace(
                "    assert add(2, 3) == 5", "    if False:\n        assert add(2, 3) == 5"
            ),
            "constant condition",
        ),
        (
            lambda t: t.replace(
                "def test_add():\n", "def test_add():\n    raise unittest.SkipTest('x')\n"
            ),
            "skip",
        ),
    ],
)
def test_weakened_tests_are_refused(change: object, message: str) -> None:
    patched = change(TEST)  # type: ignore[operator]
    found = problems("tests/test_app.py", TEST, patched)
    assert any(message in problem for problem in found), found


def test_adding_a_test_is_fine() -> None:
    patched = TEST + "\n\ndef test_zero():\n    assert add(0, 0) == 0\n"
    assert problems("tests/test_app.py", TEST, patched) == []


def test_aliased_skip_markers_are_refused() -> None:
    patched = TEST.replace("import pytest\n", "import pytest\nfrom pytest import skip\n").replace(
        "    assert add(2, 3) == 5\n", "    skip()\n    assert add(2, 3) == 5\n"
    )
    assert any("skip" in p for p in problems("tests/test_app.py", TEST, patched))


def test_skip_markers_are_refused_outside_test_files_too() -> None:
    patched = "import pytest\n" + APP + "pytest.skip('later')\n"
    assert any("skip" in problem for problem in problems("app.py", APP, patched))


def test_self_skiptest_is_refused() -> None:
    original = (
        "import unittest\n\n\nclass T(unittest.TestCase):\n"
        "    def test_a(self):\n        self.assertTrue(True)\n"
    )
    patched = original.replace(
        "        self.assertTrue(True)",
        "        self.skipTest('later')\n        self.assertTrue(True)",
    )
    assert any("skip" in p for p in problems("tests/test_t.py", original, patched))


def test_a_utf7_encoding_declaration_is_refused() -> None:
    # Python would decode "+AAo-..." as a new line of code; as text it is only a comment.
    hidden = "# -*- coding: utf-7 -*-\n" + APP + "# ok +AAo-import os+ADs-os.system(+ACI-id+ACI-)\n"
    assert problems("app.py", APP, hidden) == [
        "the patched file declares an encoding other than UTF-8, ASCII or Latin-1"
    ]


def test_a_utf8_declaration_is_fine() -> None:
    fixed = "# -*- coding: utf-8 -*-\n" + APP.replace('["ls", name]', '["ls", "--", name]')
    assert problems("app.py", APP, fixed) == []


def test_deeply_nested_code_is_rejected_not_crashing() -> None:
    nested = APP + "x = " + "-" * 20_000 + "1\n"
    assert problems("app.py", APP, nested)


# --- half fixes that keep or add a problem (phase 8) -----------------------------------------

BEFORE = """import logging
import os


def parse(value):
    return int(value)
"""


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (
            "    try:\n        return int(value)\n    except ValueError:\n"
            "        return eval(value)\n",
            "fallback in an exception handler",
        ),
        (
            "    try:\n        return int(value)\n    except ValueError:\n"
            "        import yaml\n        return yaml.load(value, Loader=yaml.Loader)\n",
            "fallback in an exception handler",
        ),
        ('    logging.info("token=%s", value)\n    return int(value)\n', "looks like a secret"),
        ("    password = value\n    print(password)\n    return 1\n", "looks like a secret"),
        ('    logging.warning(f"bad key {api_key}")\n    return 1\n', "looks like a secret"),
        ('    return os.getenv("API_TOKEN", "fallback-value")\n', "hardcoded fallback"),
        ('    return os.getenv("API_TOKEN", default="fallback")\n', "hardcoded fallback"),
        ('    return os.environ.get("API_TOKEN") or "fallback"\n', "hardcoded fallback"),
        ('    logging.info("password=%s" % value)\n    return 1\n', "looks like a secret"),
        ('    logging.info("access_token=" + value)\n    return 1\n', "looks like a secret"),
        ('    print("key {}".format(api_key))\n    return 1\n', "looks like a secret"),
        ('    print(cfg["password"])\n    return 1\n', "looks like a secret"),
        ('    log.info("using " + token)\n    return 1\n', "looks like a secret"),
        ("    from logging import info\n    info(password)\n    return 1\n", "looks like a secret"),
        ("    os.chmod(value, mode=0o777)\n    return 1\n", "writable by others"),
        (
            "    import stat\n    os.chmod(value, stat.S_IRWXU | stat.S_IWOTH)\n    return 1\n",
            "writable by others",
        ),
        (
            '    db_password = value\n    logging.debug("%s", db_password)\n    return 1\n',
            "looks like a secret",
        ),
        ("    apiKey = value\n    print(apiKey)\n    return 1\n", "looks like a secret"),
        ("    os.umask(0)\n    return 1\n", "umask"),
        ("    os.chmod(value, 0o777)\n    return 1\n", "writable by others"),
    ],
)
def test_half_fixes_are_refused(body: str, message: str) -> None:
    patched = BEFORE.replace("    return int(value)\n", body)
    assert any(message in problem for problem in problems("app.py", BEFORE, patched))


@pytest.mark.parametrize(
    "body",
    [
        "    try:\n        return int(value)\n    except ValueError:\n        return None\n",
        '    logging.info("parsed value for %s", value)\n    return int(value)\n',
        '    logging.info("token refreshed")\n    return int(value)\n',
        '    return os.getenv("APP_MODE", "production")\n',
        '    return os.getenv("API_TOKEN", "")\n',
        "    os.umask(0o077)\n    return 1\n",
        "    os.chmod(value, 0o644)\n    return 1\n",
        # Not loggers: math.log and an argument parser's error().
        "    import math\n    return math.log(token)\n",
        "    parser.error(token)\n    return 1\n",
        # Words that only contain a secret-like word are not secrets.
        '    passed = value\n    logging.info("tests passed: %s", passed)\n    return 1\n',
        "    max_tokens = value\n    print(max_tokens)\n    return 1\n",
        '    logging.info("bypass: %s", value)\n    return 1\n',
    ],
)
def test_ordinary_code_near_those_patterns_passes(body: str) -> None:
    patched = BEFORE.replace("    return int(value)\n", body)
    assert problems("app.py", BEFORE, patched) == []


def test_only_running_or_deserializing_calls_count_as_unsafe_fallbacks() -> None:
    # vars() already in the file, moved into a handler: not an unsafe fallback.
    before = "def describe(obj):\n    return vars(obj)\n"
    after = (
        "def describe(obj):\n    try:\n        return obj.describe()\n"
        "    except AttributeError:\n        return vars(obj)\n"
    )
    assert problems("app.py", before, after) == []
    moved_eval = before.replace("vars(obj)", "eval(obj)")
    kept = after.replace("vars(obj)", "eval(obj)")
    assert any("fallback" in p for p in problems("app.py", moved_eval, kept))


@pytest.mark.parametrize(
    ("before_body", "after_body", "message"),
    [
        # One secret log removed, another added: still adds one.
        (
            '    logging.info("password=%s", value)\n    return 1\n',
            '    logging.info("token=%s", value)\n    return 1\n',
            "looks like a secret",
        ),
        # The chmod fixed, the umask cleared instead.
        (
            "    os.chmod(value, 0o777)\n    return 1\n",
            "    os.chmod(value, 0o755)\n    os.umask(0)\n    return 1\n",
            "umask",
        ),
    ],
)
def test_swapping_one_bad_pattern_for_another_is_refused(
    before_body: str, after_body: str, message: str
) -> None:
    before = BEFORE.replace("    return int(value)\n", before_body)
    after = BEFORE.replace("    return int(value)\n", after_body)
    assert any(message in problem for problem in problems("app.py", before, after))
