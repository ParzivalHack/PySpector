"""
Tests for Group A taint-driven rules: SETATTR831, DELATTR834, FORMAT864,
FSTRING867, TRANSLATE912, REPLACE879, SER522, RAND810.

Each test proves:
  - True positive: tainted arg → rule fires
  - True negative: constant arg → rule does NOT fire
"""

import os
import sys
import tempfile
import textwrap
import warnings
from pathlib import Path

import pytest


def _wrap(code: str) -> str:
    indented = "\n".join("    " + l for l in textwrap.dedent(code).splitlines())
    return f"def _view(request):\n{indented}\n"


def run_pyspector(code: str, filename: str = "app.py") -> list[dict]:
    from pyspector._rust_core import run_scan
    from pyspector.config import get_default_rules
    import ast as _ast, json as _json
    from pyspector.cli import AstEncoder

    wrapped = _wrap(code)
    rules_toml = get_default_rules()

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, filename)
        Path(path).write_text(wrapped)
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore")
            try:
                tree = _ast.parse(wrapped)
                ast_json = _json.dumps(tree, cls=AstEncoder)
            except Exception:
                ast_json = "{}"
        files = [{"file_path": filename, "content": wrapped, "ast_json": ast_json}]
        results = run_scan(tmpdir, rules_toml, {"exclude": []}, files)

    return [{"rule_id": r.rule_id, "line_number": r.line_number} for r in results]


def fires(code, rule_id, **kw):
    return [f for f in run_pyspector(code, **kw) if f["rule_id"] == rule_id]


# ============================================================
# SETATTR831 — arbitrary attribute write via tainted name
# ============================================================

class TestSetattr831:
    def test_tainted_attr_name_fires(self):
        code = """
            attr = request.GET.get('field')
            setattr(user, attr, 'value')
        """
        assert fires(code, "SETATTR831"), "SETATTR831 must fire: tainted attr name to setattr"

    def test_subscript_source_fires(self):
        code = """
            attr = request.POST['field']
            setattr(obj, attr, True)
        """
        assert fires(code, "SETATTR831"), "SETATTR831 must fire with subscript source"

    def test_constant_attr_safe(self):
        code = """
            setattr(obj, 'username', 'alice')
        """
        assert not fires(code, "SETATTR831"), "SETATTR831 must NOT fire for constant attr name"


# ============================================================
# DELATTR834 — arbitrary attribute deletion via tainted name
# ============================================================

class TestDelattr834:
    def test_tainted_attr_name_fires(self):
        code = """
            attr = request.GET.get('field')
            delattr(obj, attr)
        """
        assert fires(code, "DELATTR834"), "DELATTR834 must fire: tainted attr name to delattr"

    def test_constant_attr_safe(self):
        code = """
            delattr(obj, 'cache')
        """
        assert not fires(code, "DELATTR834"), "DELATTR834 must NOT fire for constant attr"


# ============================================================
# FORMAT864 — tainted format string used as template
# ============================================================

class TestFormat864:
    def test_tainted_receiver_fires(self):
        """template = request.GET.get('t'); template.format(user=user)"""
        code = """
            template = request.GET.get('template')
            result = template.format(user=user_obj)
        """
        assert fires(code, "FORMAT864"), "FORMAT864 must fire: tainted string used as .format() template"

    def test_tainted_via_subscript_fires(self):
        code = """
            tmpl = request.GET['template']
            output = tmpl.format(name='Alice')
        """
        assert fires(code, "FORMAT864"), "FORMAT864 must fire with subscript source"

    def test_constant_template_safe(self):
        code = """
            result = 'Hello {name}!'.format(name=user.name)
        """
        assert not fires(code, "FORMAT864"), "FORMAT864 must NOT fire for constant template"

    def test_tainted_arg_safe(self):
        # FORMAT864 only fires when the TEMPLATE (receiver) is tainted.
        # A safe hardcoded template with tainted ARGUMENTS is not SSTI.
        # FP case: msg = '{} is a symlink'; raise FileExistsError(msg.format(cfile))
        code = """
            msg = '{} is not a valid path'
            raise ValueError(msg.format(request.GET.get('path')))
        """
        assert not fires(code, "FORMAT864"), "FORMAT864 must NOT fire when only the arg is tainted"


# ============================================================
# FSTRING867 — tainted variable inside f-string
# ============================================================

class TestFstring867:
    # FSTRING867 is disabled as a standalone sink — f-string taint propagates forward
    # to downstream sinks (LOG741, PY101, PATH813, etc.) which report it more precisely.
    # As a standalone sink it fires on every display/error string in large codebases.
    def test_tainted_variable_silent_disabled(self):
        code = """
            cmd = request.GET.get('cmd')
            query = f'SELECT * FROM {cmd}'
        """
        assert not fires(code, "FSTRING867"), "FSTRING867 disabled: downstream PY101 covers this"

    def test_constant_fstring_safe(self):
        code = """
            name = 'Alice'
            greeting = f'Hello {name}!'
        """
        assert not fires(code, "FSTRING867"), "FSTRING867 must NOT fire for f-string with local constant"


# ============================================================
# REPLACE879 — tainted replace arg used for filter bypass
# ============================================================

class TestReplace879:
    def test_tainted_silent_disabled(self):
        # REPLACE879 disabled: str.replace() is a pure data transformation.
        # Also caused FPs from os.replace(), node.replace(), code.replace() — any
        # method named 'replace' matched regardless of receiver type.
        code = """
            bad = request.GET.get('pattern')
            result = sanitized.replace(bad, '')
        """
        assert not fires(code, "REPLACE879"), "REPLACE879 disabled: str.replace() is not a security sink alone"

    def test_constant_replace_safe(self):
        code = """
            result = user_name.replace('<', '&lt;')
        """
        assert not fires(code, "REPLACE879"), "REPLACE879 must NOT fire for constant search/replace"


# ============================================================
# TRANSLATE912 — tainted translation table (sanitization bypass)
# ============================================================

class TestTranslate912:
    def test_tainted_silent_disabled(self):
        # TRANSLATE912 disabled: str.translate() is a character-mapping transformation.
        # The downstream result needs to reach a dangerous sink to be exploitable.
        code = """
            table_data = request.GET.get('table')
            result = user_input.translate(table_data)
        """
        assert not fires(code, "TRANSLATE912"), "TRANSLATE912 disabled: translate is not a security sink alone"

    def test_constant_table_safe(self):
        code = """
            import str
            result = text.translate(str.maketrans('abc', 'xyz'))
        """
        assert not fires(code, "TRANSLATE912"), "TRANSLATE912 must NOT fire for constant table"


# ============================================================
# RAND810 — tainted seed → predictable PRNG
# ============================================================

class TestRand810:
    def test_tainted_seed_fires(self):
        code = """
            import random
            seed = request.GET.get('seed')
            random.seed(seed)
        """
        assert fires(code, "RAND810"), "RAND810 must fire: tainted seed to random.seed()"

    def test_constant_seed_safe(self):
        code = """
            import random
            random.seed(42)
        """
        assert not fires(code, "RAND810"), "RAND810 must NOT fire for constant seed"


# ============================================================
# SER522 — tainted object to serializer
# ============================================================

class TestSer522:
    def test_tainted_object_fires(self):
        code = """
            data = request.POST.get('data')
            result = serialize('json', data)
        """
        assert fires(code, "SER522"), "SER522 must fire: tainted object to serialize()"

    def test_constant_object_safe(self):
        code = """
            result = serialize('json', MyModel.objects.all())
        """
        assert not fires(code, "SER522"), "SER522 must NOT fire for untainted queryset"


# ============================================================
# Regression — existing rules still fire
# ============================================================

class TestRegression:
    def test_getattr828_still_fires(self):
        code = """
            attr = request.GET.get('field')
            getattr(user, attr)
        """
        assert fires(code, "GETATTR828"), "GETATTR828 regression"

    def test_py102_still_fires(self):
        code = """
            cmd = request.get('command')
            subprocess.run(cmd)
        """
        assert fires(code, "PY102"), "PY102 regression"

    def test_open1149_still_fires(self):
        code = """
            path = request.GET.get('file')
            open(path)
        """
        assert fires(code, "OPEN1149"), "OPEN1149 regression"
