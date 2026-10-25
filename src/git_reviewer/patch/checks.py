"""Deterministic checks on a patched Python file, before anything runs (docs/ARCHITECTURE.md §10.3;
SECURITY.md T-03, T-19).

The original and the patched file are parsed and compared, so only what the patch adds counts:
- imports: a new third-party import (a dependency) or a new import of a module for network,
  processes, native code, serialization or dynamic imports;
- uses: more references to eval/exec/compile/__import__, os.system/os.exec*/os.spawn*,
  subprocess, socket, HTTP clients, pickle/marshal loads or decoding helpers (called or not, so
  `e = eval` counts), or getattr-style calls on computed names. Import aliases are resolved first:
  `from os import system` makes `system(...)` a use of os.system;
- encoding: the patched file must keep a UTF-8/ASCII/Latin-1 encoding declaration (or none):
  with `# coding: utf-7`, Python would run code that these checks, the scanners and the user only
  see as a comment. Both versions are parsed from bytes, as Python reads them;
- star imports: any new `from X import *` (it would hide which names are used);
- obfuscation: long new string literals, more chr() calls, new invisible or control characters;
- swallowed errors: more `except:` / `except Exception` / `except BaseException` handlers, also
  inside a tuple such as `except (ValueError, Exception)`;
- weakened tests: a removed or changed assertion or test function, a new skip/xfail/SkipTest, or a
  new early `return`/`raise` or constant condition (`if False:`) inside a test function.
The patch auditor checks the same things with judgment; these checks cannot be talked out of it.
Known limit: a denylist cannot follow every indirection (`o = os; o.system(...)`); such patches
still face the sandbox, the auditor and the user's reading of the diff (SECURITY.md T-03).
"""

from __future__ import annotations

import ast
import sys
import unicodedata
from collections import Counter

from git_reviewer.guardians.execution import is_test_infrastructure
from git_reviewer.static.analyze import declared_coding_is_safe

_RISKY_MODULES = frozenset(
    {
        "socket",
        "ssl",
        "http",
        "urllib",
        "ftplib",
        "poplib",
        "imaplib",
        "smtplib",
        "telnetlib",
        "xmlrpc",
        "asyncio",
        "subprocess",
        "pty",
        "ctypes",
        "multiprocessing",
        "pickle",
        "marshal",
        "shelve",
        "importlib",
        "runpy",
        "code",
        "codeop",
        "webbrowser",
        "builtins",
    }
)
_DANGEROUS_CALLS = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "__builtins__",
        "chr",
        "globals",
        "locals",
        "vars",
        "os.system",
        "os.popen",
        "os.fork",
        "os.kill",
        "os._exit",
        "os.abort",
        "pickle.load",
        "pickle.loads",
        "marshal.loads",
        "base64.b64decode",
        "base64.b32decode",
        "base64.a85decode",
        "base64.b85decode",
        "codecs.decode",
        "bytes.fromhex",
        "bytearray.fromhex",
        "zlib.decompress",
    }
)
_DANGEROUS_PREFIXES = (
    "os.exec",
    "os.spawn",
    "os.posix_spawn",
    "subprocess.",
    "socket.",
    "urllib.",
    "http.",
    "requests.",
    "httpx.",
    "ctypes.",
    "importlib.",
)
_COMPUTED_NAME_CALLS = frozenset({"getattr", "setattr", "delattr"})
_SKIP_MARKERS = frozenset(
    {
        "pytest.mark.skip",
        "pytest.mark.skipif",
        "pytest.mark.xfail",
        "pytest.skip",
        "pytest.xfail",
        "pytest.importorskip",
        "pytest.skip.Exception",
        "unittest.skip",
        "unittest.skipIf",
        "unittest.skipUnless",
        "unittest.expectedFailure",
        "unittest.SkipTest",
        "SkipTest",
    }
)
_BROAD_EXCEPTIONS = frozenset({"Exception", "BaseException"})
_MAX_LITERAL = 200


def problems(path: str, original: str, patched: str) -> list[str]:
    """Why the patch is rejected (empty when every check passes)."""
    if not declared_coding_is_safe(patched.encode("utf-8")):
        return ["the patched file declares an encoding other than UTF-8, ASCII or Latin-1"]
    try:
        return _problems(path, original, patched)
    except (RecursionError, MemoryError):
        # Deeply nested code (attacker-controlled) must reject the patch, not crash the review.
        return ["the patched file is too complex to check"]


def _problems(path: str, original: str, patched: str) -> list[str]:
    try:
        after = ast.parse(patched.encode("utf-8"))
    except (SyntaxError, ValueError):
        return ["the patched file is not valid Python"]
    try:
        before = ast.parse(original.encode("utf-8"))
    except (SyntaxError, ValueError):
        before = ast.Module(body=[], type_ignores=[])  # everything in the patch counts as new
    found: list[str] = []
    found += _import_problems(before, after)
    if _star_imports(after) > _star_imports(before):
        found.append("adds a star import (from ... import *)")
    found += _call_problems(before, after)
    found += _obfuscation_problems(before, after, original, patched)
    if _broad_handlers(after) > _broad_handlers(before):
        found.append("adds an exception handler that catches everything")
    if is_test_infrastructure(path) or _defines_tests(before):
        found += _test_problems(before, after)
    elif _skips(after) > _skips(before):
        found.append("adds a skip or xfail marker")
    return list(dict.fromkeys(found))


def _import_problems(before: ast.Module, after: ast.Module) -> list[str]:
    found: list[str] = []
    for module in sorted(_imports(after) - _imports(before)):
        if module in _RISKY_MODULES:
            found.append(f"adds an import of {module} (network, processes or dynamic code)")
        elif module not in sys.stdlib_module_names:
            found.append(f"adds an import of {module}, which is not in the standard library")
    return found


def _imports(tree: ast.Module) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            modules.add(node.module.split(".")[0])
    return modules


def _call_problems(before: ast.Module, after: ast.Module) -> list[str]:
    old, new = _risky_uses(before), _risky_uses(after)
    return [f"adds a use of {name}" for name in sorted(new) if new[name] > old[name]]


def _risky_uses(tree: ast.Module) -> Counter[str]:
    aliases = _aliases(tree)
    uses: Counter[str] = Counter()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute | ast.Name):
            name = _canonical(_dotted(node), aliases)
            if name in _DANGEROUS_CALLS or name.startswith(_DANGEROUS_PREFIXES):
                uses[name] += 1
        elif isinstance(node, ast.Call):
            name = _canonical(_dotted(node.func), aliases)
            if name not in _COMPUTED_NAME_CALLS:
                continue
            attribute = node.args[1] if len(node.args) >= 2 else None
            if not (isinstance(attribute, ast.Constant) and isinstance(attribute.value, str)):
                uses[f"{name} with a computed name"] += 1
                continue
            # getattr(os, "system") is a use of os.system.
            owner = _canonical(_dotted(node.args[0]), aliases)
            target = f"{owner}.{attribute.value}" if owner else attribute.value
            if target in _DANGEROUS_CALLS or target.startswith(_DANGEROUS_PREFIXES):
                uses[target] += 1
    return uses


def _star_imports(tree: ast.Module) -> int:
    return sum(
        1
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names)
    )


def _aliases(tree: ast.Module) -> dict[str, str]:
    """Local name -> what it stands for: `import os as o` (o -> os), `from os import system`
    (system -> os.system)."""
    names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    names[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for alias in node.names:
                names[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return names


def _canonical(name: str, aliases: dict[str, str]) -> str:
    head, dot, rest = name.partition(".")
    if head not in aliases:
        return name
    return f"{aliases[head]}{dot}{rest}"


def _obfuscation_problems(
    before: ast.Module, after: ast.Module, original: str, patched: str
) -> list[str]:
    found: list[str] = []
    if _long_literals(after) - _long_literals(before):
        found.append(f"adds a string literal longer than {_MAX_LITERAL} characters")
    if _hidden_characters(patched) > _hidden_characters(original):
        found.append("adds invisible or control characters")
    return found


def _long_literals(tree: ast.Module) -> set[str | bytes]:
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str | bytes)
        and len(node.value) > _MAX_LITERAL
    }


def _hidden_characters(text: str) -> int:
    return sum(
        1
        for char in text
        if char not in "\n\t" and unicodedata.category(char) in {"Cc", "Cf", "Co", "Cs", "Zl", "Zp"}
    )


def _broad_handlers(tree: ast.Module) -> int:
    count = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        types = node.type.elts if isinstance(node.type, ast.Tuple) else [node.type]
        if any(kind is None or _dotted(kind) in _BROAD_EXCEPTIONS for kind in types):
            count += 1
    return count


def _test_problems(before: ast.Module, after: ast.Module) -> list[str]:
    found: list[str] = []
    if _assertions(before) - _assertions(after):
        found.append("removes or changes an assertion")
    if _test_functions(before) - _test_functions(after):
        found.append("removes or renames a test")
    if _skips(after) > _skips(before):
        found.append("adds a skip or xfail marker")
    if _test_exits(after) > _test_exits(before):
        found.append("adds an early return, a raise or a constant condition inside a test")
    return found


def _skips(tree: ast.Module) -> int:
    """Skip markers and calls, including self.skipTest(...)."""
    calls = sum(
        1
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "skipTest"
    )
    return _names(tree, _SKIP_MARKERS).total() + calls


def _test_exits(tree: ast.Module) -> int:
    """`return`, `raise` and `if`/`while` on a constant inside test functions: ways to stop a test
    before its assertions while leaving them in place."""
    count = 0
    for function in ast.walk(tree):
        if not (
            isinstance(function, ast.FunctionDef | ast.AsyncFunctionDef)
            and function.name.startswith("test")
        ):
            continue
        count += sum(1 for node in ast.walk(function) if _stops_a_test(node))
    return count


def _stops_a_test(node: ast.AST) -> bool:
    if isinstance(node, ast.Return | ast.Raise):
        return True
    return isinstance(node, ast.If | ast.While) and isinstance(node.test, ast.Constant)


def _assertions(tree: ast.Module) -> Counter[str]:
    """assert statements and unittest assert* calls, compared exactly."""
    found: Counter[str] = Counter()
    for node in ast.walk(tree):
        is_assert_call = (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr.startswith("assert")
        )
        if isinstance(node, ast.Assert) or is_assert_call:
            found[ast.dump(node)] += 1
    return found


def _test_functions(tree: ast.Module) -> set[str]:
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name.startswith("test")
    }


def _defines_tests(tree: ast.Module) -> bool:
    return bool(_test_functions(tree))


def _names(tree: ast.Module, wanted: frozenset[str]) -> Counter[str]:
    """Occurrences of dotted names (as decorators or calls) such as pytest.mark.skip, with
    import aliases resolved (`from pytest import skip`)."""
    aliases = _aliases(tree)
    found: Counter[str] = Counter()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute | ast.Name):
            name = _canonical(_dotted(node), aliases)
            if name in wanted:
                found[name] += 1
    return found


def _dotted(node: ast.expr) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""
