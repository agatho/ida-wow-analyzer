"""
Static self-checks for the TC WoW Analyzer -- runnable WITHOUT IDA.

Every check here corresponds to a class of bug that actually shipped and stayed
undetected for months, because the failure mode was silence rather than a
crash:

  1. check_imports        -- `batch/headless.py` imported two symbols that do
                             not exist (`batch_semantic_decompile`,
                             `run_conformance_analysis`). ImportError killed the
                             `complete`/`llm_only`/`quality` presets *before*
                             the IDB save.
  2. check_sql            -- `subsystem_catalog` queried `vtables.vtable_ea`;
                             the column is `ea`. The OperationalError was
                             swallowed by `except Exception`, so an entire
                             analysis pass was a permanent no-op.
  3. check_registry       -- the run loop had 71 analyzers, the registry 70.
                             The missing one was invisible in the Analyzer Index.
  4. check_kv_keys        -- seven kv_store keys were read by one module and
                             written under a different name by another. Each is
                             a total, silent loss of that analyzer's output.
  5. check_analyzer_wrappers -- every `_run_*` wrapper must import a symbol that
                             exists in its target module.

Usage:
    python tests/static_checks.py            # from the plugin directory
    python -m tests.static_checks
Exit code is non-zero if any check fails, so it can gate a commit.
"""

import ast
import os
import re
import sqlite3
import sys


PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {"__pycache__", ".git", "tests"}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _py_files(root=None):
    root = root or PLUGIN_ROOT
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            if name.endswith(".py"):
                yield os.path.join(dirpath, name)


def _rel(path):
    return os.path.relpath(path, PLUGIN_ROOT).replace("\\", "/")


def _module_path(dotted):
    """tc_wow_analyzer.core.db -> <root>/core/db.py (or package __init__)."""
    if not dotted.startswith("tc_wow_analyzer"):
        return None
    parts = dotted.split(".")[1:]
    if not parts:
        return os.path.join(PLUGIN_ROOT, "__init__.py")
    base = os.path.join(PLUGIN_ROOT, *parts)
    if os.path.isfile(base + ".py"):
        return base + ".py"
    if os.path.isfile(os.path.join(base, "__init__.py")):
        return os.path.join(base, "__init__.py")
    return None


def _top_level_names(path):
    """Names a module exposes: defs, classes, assignments, and re-imports."""
    try:
        tree = ast.parse(open(path, encoding="utf-8").read())
    except Exception:
        return set()
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.Try):
            # conditional imports (ida_kernwin etc.) live in try blocks
            for sub in ast.walk(node):
                if isinstance(sub, (ast.Import, ast.ImportFrom)):
                    for alias in sub.names:
                        names.add(alias.asname or alias.name.split(".")[0])
                elif isinstance(sub, ast.Assign):
                    for target in sub.targets:
                        if isinstance(target, ast.Name):
                            names.add(target.id)
    return names


# ---------------------------------------------------------------------------
# 1. every intra-package import resolves
# ---------------------------------------------------------------------------

def check_imports():
    problems = []
    cache = {}
    for path in _py_files():
        try:
            tree = ast.parse(open(path, encoding="utf-8").read())
        except SyntaxError as exc:
            problems.append(f"{_rel(path)}: SYNTAX ERROR: {exc}")
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or not node.module:
                continue
            if not node.module.startswith("tc_wow_analyzer"):
                continue
            target = _module_path(node.module)
            if target is None:
                problems.append(
                    f"{_rel(path)}:{node.lineno}: no such module "
                    f"'{node.module}'")
                continue
            if target not in cache:
                cache[target] = _top_level_names(target)
            available = cache[target]
            for alias in node.names:
                if alias.name == "*":
                    continue
                if alias.name in available:
                    continue
                # could be a submodule: from tc_wow_analyzer.core import db
                if _module_path(f"{node.module}.{alias.name}"):
                    continue
                problems.append(
                    f"{_rel(path)}:{node.lineno}: '{node.module}' has no "
                    f"'{alias.name}'")
    return problems


# ---------------------------------------------------------------------------
# 2. every constant SQL literal is valid against the real schema
# ---------------------------------------------------------------------------

def _schema_sql():
    src = open(os.path.join(PLUGIN_ROOT, "core", "db.py"), encoding="utf-8").read()
    match = re.search(r'SCHEMA_SQL\s*=\s*("""|\'\'\')(.*?)\1', src, re.S)
    if not match:
        raise RuntimeError("SCHEMA_SQL not found in core/db.py")
    return match.group(2)


# Deliberately strict: a bare "replace" or "Update Fields" is English prose,
# not SQL. Requiring the clause that follows the verb keeps prose out.
_SQL_START = re.compile(
    r"^\s*("
    r"SELECT\s+.+?\s+FROM\s+\w"
    r"|INSERT\s+(OR\s+\w+\s+)?INTO\s+\w"
    r"|REPLACE\s+INTO\s+\w"
    r"|UPDATE\s+\w+\s+SET\s+\w"
    r"|DELETE\s+FROM\s+\w"
    r")", re.I | re.S)


def _joined_string(node):
    """Concatenated string literal -> text, or None if it is not constant."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _joined_string(node.left)
        right = _joined_string(node.right)
        if left is not None and right is not None:
            return left + right
    if isinstance(node, ast.JoinedStr):
        return None  # f-string: table/column may be dynamic
    return None


def check_sql():
    problems = []
    conn = sqlite3.connect(":memory:")
    conn.executescript(_schema_sql())
    # Tables created lazily outside SCHEMA_SQL still have to be known here.
    conn.executescript(
        "CREATE TABLE IF NOT EXISTS cfunc_cache ("
        " ea INTEGER PRIMARY KEY, pseudocode TEXT, serialized BLOB,"
        " func_hash TEXT, created_at REAL);")

    for path in _py_files():
        try:
            tree = ast.parse(open(path, encoding="utf-8").read())
        except SyntaxError:
            continue

        # A string that is only PART of a larger expression (concatenation with
        # a variable, an f-string, %-formatting) is not a complete statement --
        # evaluating the fragment on its own produces noise, not findings.
        consumed = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr) or (
                    isinstance(node, ast.BinOp)
                    and _joined_string(node) is None):
                for child in ast.walk(node):
                    if child is not node:
                        consumed.add(id(child))

        for node in ast.walk(tree):
            if id(node) in consumed:
                continue
            text = _joined_string(node)
            if not text or not _SQL_START.match(text):
                continue
            if "{" in text or "%s" in text or "%d" in text:
                continue  # dynamic identifier, cannot be checked statically
            try:
                conn.execute("EXPLAIN " + text, [None] * text.count("?"))
            except sqlite3.Error as exc:
                problems.append(
                    f"{_rel(path)}:{node.lineno}: {exc} :: "
                    f"{' '.join(text.split())[:110]}")
    return problems


# ---------------------------------------------------------------------------
# 3. analyzer run loop and registry agree
# ---------------------------------------------------------------------------

def check_registry():
    problems = []
    init_path = os.path.join(PLUGIN_ROOT, "analyzers", "__init__.py")
    src = open(init_path, encoding="utf-8").read()
    match = re.search(r"\n    analyzers = \[(.*?)\n    \]\n", src, re.S)
    if not match:
        return ["analyzers/__init__.py: could not locate the run-loop list"]
    run_loop = re.findall(r'\(\s*"([^"]+)"\s*,\s*_run_', match.group(1))

    reg_src = open(os.path.join(PLUGIN_ROOT, "analyzers", "registry.py"),
                   encoding="utf-8").read()
    reg_names = re.findall(r'"name"\s*:\s*"([^"]+)"', reg_src)
    if not reg_names:
        reg_names = re.findall(r'AnalyzerInfo\(\s*"([^"]+)"', reg_src)

    for name in run_loop:
        if name not in reg_names:
            problems.append(f"registry.py: '{name}' runs but is not registered")
    for name in reg_names:
        if name not in run_loop:
            problems.append(f"registry.py: '{name}' is registered but never runs")

    dupes = {n for n in run_loop if run_loop.count(n) > 1}
    for name in sorted(dupes):
        problems.append(f"analyzers/__init__.py: '{name}' listed twice")
    return problems


# ---------------------------------------------------------------------------
# 4. every kv_store key that is read is also written somewhere
# ---------------------------------------------------------------------------

_KV_SET = re.compile(r'kv_set\(\s*(?:[\w.]+\s*,\s*)?["\']([^"\'{}]+)["\']')
# ui/web_dashboard.py reads the DB directly via a local _kv_get(conn, key)
# helper, so the connection argument has to be tolerated here.
_KV_GET = re.compile(r'_?kv_get\(\s*(?:[\w.]+\s*,\s*)?["\']([^"\'{}]+)["\']')
# A module-level KV_* / _KV_* constant is a deliberate key declaration.
_KV_CONST = re.compile(r'^\s*_?KV_\w*\s*=\s*["\']([^"\']+)["\']', re.M)


def _kv_keys_constants():
    """Name -> value for every constant in core/kv_keys.py."""
    path = os.path.join(PLUGIN_ROOT, "core", "kv_keys.py")
    values = {}
    if not os.path.isfile(path):
        return values
    tree = ast.parse(open(path, encoding="utf-8").read())
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            for target in node.targets:
                if isinstance(target, ast.Name) and isinstance(node.value.value, str):
                    values[target.id] = node.value.value
    return values


_KV_ATTR = re.compile(r'kv_(?:set|get)\(\s*(?:[\w.]+\s*,\s*)?kv_keys\.(\w+)')


def check_kv_keys():
    written, read = set(), {}
    constants = _kv_keys_constants()
    for path in _py_files():
        src = open(path, encoding="utf-8").read()
        written.update(_KV_SET.findall(src))
        written.update(_KV_CONST.findall(src))
        # kv_set(kv_keys.FOO, ...) -- resolve through core/kv_keys.py
        for match in re.finditer(
                r'kv_set\(\s*(?:[\w.]+\s*,\s*)?kv_keys\.(\w+)', src):
            value = constants.get(match.group(1))
            if value:
                written.add(value)
            else:
                line = src[:match.start()].count("\n") + 1
                read.setdefault(f"<undefined kv_keys.{match.group(1)}>",
                                []).append(f"{_rel(path)}:{line}")
        for match in re.finditer(
                r'kv_get\(\s*(?:[\w.]+\s*,\s*)?kv_keys\.(\w+)', src):
            line = src[:match.start()].count("\n") + 1
            value = constants.get(match.group(1))
            key = value if value else f"<undefined kv_keys.{match.group(1)}>"
            read.setdefault(key, []).append(f"{_rel(path)}:{line}")
        for match in _KV_GET.finditer(src):
            line = src[:match.start()].count("\n") + 1
            read.setdefault(match.group(1), []).append(f"{_rel(path)}:{line}")

    problems = []
    for key, sites in sorted(read.items()):
        if key in written:
            continue
        # Only a real dynamic-suffix pattern ("behavioral_spec:" + tc_name)
        # counts as "written". A loose prefix match would have excused exactly
        # the bugs this check exists to find: reading "conformance" when the
        # writer stores "conformance_report", or "behavioral_spec" when the
        # writer stores "behavioral_specs".
        if any(w.startswith(key + ":") for w in written):
            continue
        problems.append(
            f"kv key '{key}' is read at {', '.join(sites[:3])} "
            f"but never written")
    return problems


# ---------------------------------------------------------------------------
# 5. analyzer wrappers point at real functions
# ---------------------------------------------------------------------------

def check_analyzer_wrappers():
    problems = []
    init_path = os.path.join(PLUGIN_ROOT, "analyzers", "__init__.py")
    src = open(init_path, encoding="utf-8").read()
    tree = ast.parse(src)
    defined = {n.name for n in tree.body
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}

    match = re.search(r"\n    analyzers = \[(.*?)\n    \]\n", src, re.S)
    if match:
        for name, wrapper in re.findall(
                r'\(\s*"([^"]+)"\s*,\s*(_run_\w+)\s*\)', match.group(1)):
            if wrapper not in defined:
                problems.append(
                    f"analyzers/__init__.py: '{name}' -> {wrapper}() is not defined")
    return problems


# ---------------------------------------------------------------------------

CHECKS = (
    ("intra-package imports resolve", check_imports),
    ("SQL matches the schema", check_sql),
    ("run loop == registry", check_registry),
    ("kv keys have a writer", check_kv_keys),
    ("analyzer wrappers exist", check_analyzer_wrappers),
)


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    only = set(argv)
    failed = 0
    for title, func in CHECKS:
        if only and not any(o in title for o in only):
            continue
        try:
            problems = func()
        except Exception as exc:
            print(f"[ERROR] {title}: check itself failed: "
                  f"{type(exc).__name__}: {exc}")
            failed += 1
            continue
        if problems:
            failed += len(problems)
            print(f"[FAIL] {title} ({len(problems)} problem(s))")
            for problem in problems:
                print(f"       {problem}")
        else:
            print(f"[ OK ] {title}")
    print()
    if failed:
        print(f"{failed} problem(s) found.")
        return 1
    print("All static checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
