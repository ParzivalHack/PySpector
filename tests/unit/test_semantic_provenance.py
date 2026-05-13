"""
Tier 1 + Tier 2 semantic provenance tests.
Universal Python semantics — no framework-specific knowledge required.
"""
import os, sys, tempfile, warnings
from pathlib import Path
import pytest


def run(code, filename="app.py"):
    import ast as _ast, json as _json
    from pyspector._rust_core import run_scan
    from pyspector.config import get_default_rules
    from pyspector.cli import AstEncoder
    rules = get_default_rules()
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, filename)
        Path(p).write_text(code)
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore")
            try: aj = _json.dumps(_ast.parse(code), cls=AstEncoder)
            except: aj = "{}"
        files = [{"file_path": filename, "content": code, "ast_json": aj}]
        return [{"rule_id": r.rule_id} for r in run_scan(d, rules, {"exclude": []}, files)]


def fires(code, rule_id, filename="app.py"):
    return [f for f in run(code, filename) if f["rule_id"] == rule_id]


def _wrap(code):
    import textwrap
    ind = "\n".join("    " + l for l in textwrap.dedent(code).strip().splitlines())
    return f"def view(request):\n{ind}\n"


def taint_fires(code, rule_id):
    """Use taint engine — wraps code in a function for CFG analysis."""
    wrapped = _wrap(code)
    return fires(wrapped, rule_id)


# ─── Tier 1: Structural Python rules ────────────────────────────────────────

class TestTier1StructuralRules:

    def test_admin795_class_declaration_not_flagged(self):
        """
        'class AdminPasswordChangeForm' is a Python class declaration.
        Python syntax: class keyword → DeveloperDefined name context.
        Universal — applies to any codebase, not just Django.
        """
        code = "class AdminPasswordChangeForm(BaseForm):\n    pass\n"
        assert not fires(code, "ADMIN795"), \
            "ADMIN795 must not fire on class declarations"

    def test_admin795_fires_on_actual_inline_credential(self):
        """Lowercase variable with password=password pattern still fires."""
        # Pattern requires: admin/administrator + password + password (twice)
        code = 'admin_default_password = "password_admin"\n'
        assert fires(code, "ADMIN795", filename="config.py"), \
            "ADMIN795 must still fire when pattern has two 'password' occurrences"

    def test_g101_uppercase_constant_not_flagged(self):
        """
        INTERNAL_RESET_SESSION_TOKEN = "_password_reset_token" is a module constant.
        Python: UPPER_CASE = "literal" → DeveloperDefined provenance.
        Universal — any Python module constant.
        """
        code = 'INTERNAL_RESET_SESSION_TOKEN = "_password_reset_token"\n'
        assert not fires(code, "G101"), \
            "G101 must not fire on UPPER_CASE module constants"

    def test_g101_fires_on_lowercase_secret(self):
        """Lowercase secret variable must still fire."""
        code = 'api_secret = "mysecretkey123"\n'
        assert fires(code, "G101", filename="config.py"), \
            "G101 must fire on lowercase secret variable assignments"

    def test_symlink816_hardcoded_path_not_flagged(self):
        """
        SYMLINK816 is now taint-driven only — no pattern.
        os.symlink() with non-tainted arguments must not fire.
        """
        code = "os.symlink(original_path, symlink_path)\n"
        assert not fires(code, "SYMLINK816", filename="utils.py"), \
            "SYMLINK816 must not fire on os.symlink with non-tainted (non-HttpRequest) args"

    def test_symlink816_fires_on_user_controlled_path(self):
        """Symlink with HttpRequest-tainted source must fire via taint engine."""
        code = _wrap("src = request.GET.get('path')\nos.symlink(src, '/tmp/dst')")
        assert fires(code, "SYMLINK816"), \
            "SYMLINK816 must fire when symlink source is HttpRequest-tainted"


# ─── Tier 2: Provenance tracking ────────────────────────────────────────────

class TestTier2ProvenanceTracking:

    def test_http_request_to_getattr_fires(self):
        """HttpRequest provenance → getattr sink → fires."""
        assert taint_fires(
            "attr = request.GET.get('field')\ngetattr(obj, attr)",
            "GETATTR828"
        ), "HttpRequest provenance must trigger GETATTR828"

    def test_http_request_to_open_fires(self):
        """HttpRequest provenance → open() sink → fires."""
        assert taint_fires(
            "path = request.GET.get('file')\nopen(path)",
            "OPEN1149"
        ), "HttpRequest provenance must trigger OPEN1149"

    def test_system_generated_to_open_silent(self):
        """SystemGenerated (tempfile.mkstemp) → open() → silent."""
        assert not taint_fires(
            "import tempfile\npath = tempfile.mkstemp()[1]\nopen(path)",
            "OPEN1149"
        ), "SystemGenerated paths must not trigger OPEN1149"

    def test_developer_defined_literal_to_sql_silent(self):
        """DeveloperDefined string literal → SQL → silent (no injection risk)."""
        assert not taint_fires(
            'table_name = "my_table"\nsql = "SELECT * FROM %s" % table_name\ncursor.execute(sql)',
            "PY101"
        ), "DeveloperDefined literals must not trigger SQL injection"

    def test_http_binop_to_sql_fires(self):
        """HttpRequest → BinOp % formatting → SQL sink → fires."""
        assert taint_fires(
            "table = request.GET.get('t')\nsql = 'SELECT * FROM %s' % table\ncursor.execute(sql)",
            "PY101"
        ), "HttpRequest through BinOp % must trigger PY101"

    def test_sanitizer_clears_http_taint(self):
        """quote_name sanitizer clears HttpRequest taint → SQL sink silent."""
        assert not taint_fires(
            "raw = request.GET.get('t')\ntable = quote_name(raw)\nsql = 'SELECT * FROM %s' % table\ncursor.execute(sql)",
            "PY101"
        ), "quote_name sanitizer must clear taint before SQL sink"

    def test_http_to_setattr_fires(self):
        """HttpRequest → setattr attribute name → fires."""
        assert taint_fires(
            "attr = request.GET.get('field')\nsetattr(obj, attr, val)",
            "SETATTR831"
        ), "HttpRequest attribute name to setattr must fire"

    def test_http_fstring_silent_disabled(self):
        """FSTRING867 disabled — taint propagates to downstream sinks (PY101, LOG741, etc.)."""
        assert not taint_fires(
            "cmd = request.GET.get('cmd')\nquery = f'SELECT {cmd}'",
            "FSTRING867"
        ), "FSTRING867 disabled: downstream rules cover f-string injection contexts"

    def test_developer_defined_fstring_silent(self):
        """DeveloperDefined literal in f-string → silent."""
        assert not taint_fires(
            "name = 'Alice'\ngreeting = f'Hello {name}!'",
            "FSTRING867"
        ), "DeveloperDefined literal in f-string must be silent"


# ─── Tier 3: Constant folding (DeveloperDefined propagation) ─────────────────

class TestTier3ConstantFolding:

    def test_constant_literal_assignment_is_developer_defined(self):
        """String literal assignment → DeveloperDefined → does not reach SQL sink."""
        assert not taint_fires(
            'query = "SELECT * FROM users"\ncursor.execute(query)',
            "PY101"
        ), "String literal assignment must be DeveloperDefined — no SQL injection"

    def test_constant_plus_http_in_binop_is_http(self):
        """Constant + HttpRequest in BinOp → result is HttpRequest (unsafe)."""
        assert taint_fires(
            "user_id = request.GET.get('id')\nsql = 'SELECT * FROM users WHERE id=' + user_id\ncursor.execute(sql)",
            "PY101"
        ), "BinOp with HttpRequest operand must propagate HttpRequest taint"
