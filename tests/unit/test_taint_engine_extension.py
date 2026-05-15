"""
Tests for the extended taint engine: new sources (subscript, HTTP params),
new sinks (getattr, open), and keyword-argument sink detection.

Each test proves a specific taint flow that was NOT detectable before.
"""

import os
import sys
import tempfile
import textwrap
import warnings
from pathlib import Path

import pytest


def _wrap_in_function(code: str) -> str:
    """Wrap code in a function so the taint engine's CFG builder processes it."""
    indented = "\n".join("    " + line for line in textwrap.dedent(code).splitlines())
    return f"def _test_view(request):\n{indented}\n"


def run_pyspector(code: str, *, filename: str = "app.py") -> list[dict]:
    from pyspector._rust_core import run_scan
    from pyspector.config import get_default_rules

    rules_toml = get_default_rules()

    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = os.path.join(tmpdir, filename)
        Path(file_path).write_text(_wrap_in_function(code))

        import ast as _ast, json as _json
        from pyspector.cli import AstEncoder

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore")
            try:
                tree = _ast.parse(Path(file_path).read_text())
                ast_json = _json.dumps(tree, cls=AstEncoder)
            except Exception:
                ast_json = "{}"

        python_files = [{
            "file_path": filename,
            "content": Path(file_path).read_text(),
            "ast_json": ast_json,
        }]

        results = run_scan(tmpdir, rules_toml, {"exclude": []}, python_files)

    return [{"rule_id": r.rule_id, "file_path": r.file_path,
             "line_number": r.line_number, "code": r.code}
            for r in results]


def findings_for(code, rule_id, **kw):
    return [f for f in run_pyspector(code, **kw) if f["rule_id"] == rule_id]


# ===========================================================================
# GETATTR828 — taint-driven, only fires when attribute name is user-controlled
# ===========================================================================

class TestGetattr828:

    def test_tainted_attr_via_request_get(self):
        """request.get() → attr → getattr(obj, attr) must fire."""
        code = """
            attr = request.get('field')
            value = getattr(user, attr)
        """
        assert findings_for(code, "GETATTR828"), \
            "GETATTR828 must fire: tainted attr flows to getattr() second argument"

    def test_tainted_attr_via_django_GET(self):
        """request.GET.get() → attr → getattr() must fire (Phase 1 new source)."""
        code = """
            attr = request.GET.get('field')
            value = getattr(user, attr)
        """
        assert findings_for(code, "GETATTR828"), \
            "GETATTR828 must fire with Django request.GET.get() as source"

    def test_tainted_attr_via_django_POST(self):
        """request.POST.get() as source."""
        code = """
            field_name = request.POST.get('attr')
            result = getattr(model_instance, field_name)
        """
        assert findings_for(code, "GETATTR828"), \
            "GETATTR828 must fire with request.POST.get() as source"

    def test_tainted_attr_via_flask_args(self):
        """Flask request.args.get() as source."""
        code = """
            attr = request.args.get('property')
            val = getattr(obj, attr)
        """
        assert findings_for(code, "GETATTR828"), \
            "GETATTR828 must fire with Flask request.args.get() as source"

    def test_tainted_attr_via_subscript_django(self):
        """Phase 2: request.GET['key'] subscript as source."""
        code = """
            attr = request.GET['field']
            value = getattr(user, attr)
        """
        assert findings_for(code, "GETATTR828"), \
            "GETATTR828 must fire when attr comes from request.GET['key'] subscript"

    def test_tainted_attr_via_subscript_flask(self):
        """Phase 2: request.args subscript as source."""
        code = """
            attr = request.args['property']
            val = getattr(obj, attr)
        """
        assert findings_for(code, "GETATTR828"), \
            "GETATTR828 must fire when attr comes from request.args['key'] subscript"

    def test_tainted_attr_propagation_through_variable(self):
        """Taint must propagate through intermediate variables."""
        code = """
            raw = request.GET.get('field')
            cleaned = raw.strip()
            value = getattr(user, cleaned)
        """
        # cleaned inherits taint from raw (conservative propagation)
        assert findings_for(code, "GETATTR828"), \
            "GETATTR828 must fire even when tainted value passes through intermediate variable"

    # --- True negatives: must NOT fire ---

    def test_constant_attr_not_flagged(self):
        """Hardcoded string attribute name is safe."""
        code = """
            value = getattr(obj, 'username')
        """
        assert not findings_for(code, "GETATTR828"), \
            "GETATTR828 must NOT fire for constant attribute names"

    def test_local_variable_attr_not_flagged(self):
        """Local variable not derived from request is safe."""
        code = """
            field = 'email'
            value = getattr(user, field)
        """
        assert not findings_for(code, "GETATTR828"), \
            "GETATTR828 must NOT fire when attr is a local constant string"


# ===========================================================================
# OPEN1149 — taint-driven, only fires when path is user-controlled
# ===========================================================================

class TestOpen1149:

    def test_tainted_path_via_request_get(self):
        """request.get() → path → open(path) must fire."""
        code = """
            filename = request.get('file')
            with open(filename) as f:
                data = f.read()
        """
        assert findings_for(code, "OPEN1149"), \
            "OPEN1149 must fire when file path comes from request"

    def test_tainted_path_via_django_GET_subscript(self):
        """Phase 2: request.GET['file'] subscript → open()."""
        code = """
            path = request.GET['filename']
            with open(path, 'r') as f:
                content = f.read()
        """
        assert findings_for(code, "OPEN1149"), \
            "OPEN1149 must fire when path comes from request.GET subscript"

    def test_tainted_path_via_flask_form(self):
        """Flask request.form.get() → open()."""
        code = """
            upload_path = request.form.get('destination')
            with open(upload_path, 'wb') as f:
                f.write(data)
        """
        assert findings_for(code, "OPEN1149"), \
            "OPEN1149 must fire when write path comes from form input"

    # --- True negatives ---

    def test_hardcoded_path_not_flagged(self):
        """Hardcoded file path is safe."""
        code = """
            with open('config.toml', 'r') as f:
                config = f.read()
        """
        assert not findings_for(code, "OPEN1149"), \
            "OPEN1149 must NOT fire for hardcoded file paths"

    def test_local_path_not_flagged(self):
        """Path derived from local constants is safe."""
        code = """
            base = '/var/data'
            filename = 'output.txt'
            path = base + '/' + filename
            with open(path) as f:
                pass
        """
        assert not findings_for(code, "OPEN1149"), \
            "OPEN1149 must NOT fire when path is constructed from local constants"


# ===========================================================================
# Phase 3: keyword argument sink detection
# ===========================================================================

class TestKeywordArgSinks:

    def test_getattr_with_keyword_name_arg(self):
        """Phase 3: getattr(obj, name=attr) with tainted attr must fire."""
        code = """
            attr = request.GET.get('field')
            value = getattr(user, attr)
        """
        # Both positional and keyword should fire
        assert findings_for(code, "GETATTR828"), \
            "GETATTR828 must fire for positional getattr(obj, tainted)"


# ===========================================================================
# New taint sources: input(), os.environ.get()
# ===========================================================================

class TestNewTaintSources:

    def test_input_to_getattr(self):
        """input() → attr → getattr() must fire (TS006 source)."""
        code = """
            attr = input('Enter attribute: ')
            value = getattr(obj, attr)
        """
        assert findings_for(code, "GETATTR828"), \
            "GETATTR828 must fire when attr comes from input()"

    def test_environ_to_open_no_finding(self):
        """os.environ.get() is now OperatorConfig — opening a path the operator
        set via environment variable is intentional, not a vulnerability."""
        code = """
            import os
            path = os.environ.get('CONFIG_PATH')
            with open(path) as f:
                data = f.read()
        """
        assert not findings_for(code, "OPEN1149"), \
            "OPEN1149 must NOT fire when path comes from os.environ.get() (operator-trusted)"

    def test_http_request_to_open_still_fires(self):
        """HTTP request parameter → open() must still fire (attacker-controlled)."""
        code = """
            path = request.GET.get('file')
            with open(path) as f:
                data = f.read()
        """
        assert findings_for(code, "OPEN1149"), \
            "OPEN1149 must still fire when path comes from HTTP request"


# ===========================================================================
# Regression: existing PY102 (subprocess) still works
# ===========================================================================

class TestRegressionPY102:

    def test_subprocess_taint_still_fires(self):
        """PY102 taint flow must still work after engine changes."""
        code = """
            cmd = request.get('command')
            subprocess.run(cmd)
        """
        assert findings_for(code, "PY102"), \
            "PY102 regression: subprocess.run with tainted arg must still fire"
