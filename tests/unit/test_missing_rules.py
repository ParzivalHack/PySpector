"""
Tests for the 10 newly added security rules:
SSTI001, ORM001, ORM002, DESER725, DESER726,
TLS001, SSH001, JWT001, ZIPSLIP001, XXE001, FLASK001.
"""
import os
import sys
import tempfile
import textwrap
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))


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
    return bool([f for f in run_pyspector(code, **kw) if f["rule_id"] == rule_id])


def not_fires(code, rule_id, **kw):
    return not fires(code, rule_id, **kw)


# ============================================================
# SSTI001 — Server-Side Template Injection
# ============================================================

class TestSSTI001:
    def test_render_template_string_tainted_fires(self):
        code = """
            tmpl = request.GET.get('template')
            return render_template_string(tmpl)
        """
        assert fires(code, "SSTI001"), "SSTI001 must fire: tainted string to render_template_string"

    def test_from_string_silent_removed(self):
        # SK_SSTI002 (from_string sink) removed — from_string() is too generic.
        # It fired on TF's DeviceSpec.from_string(), any library with .from_string().
        # SSTI is still caught via render_template_string (SK_SSTI001) and
        # the jinja2.Template pattern-based rule.
        code = """
            src = request.POST.get('src')
            result = env.from_string(src).render()
        """
        assert not_fires(code, "SSTI001"), "SK_SSTI002 removed: from_string too generic"

    def test_static_template_safe(self):
        code = """
            result = render_template_string('<h1>Hello {{ name }}</h1>', name=user)
        """
        assert not_fires(code, "SSTI001"), "SSTI001 must NOT fire for static template literal"


# ============================================================
# ORM001 — SQLAlchemy text() injection
# ============================================================

class TestORM001:
    def test_fstring_in_text_fires(self):
        code = """
            uid = request.GET.get('id')
            result = session.execute(text(f"SELECT * FROM users WHERE id={uid}"))
        """
        assert fires(code, "ORM001"), "ORM001 must fire: f-string inside text()"

    def test_percent_format_in_text_fires(self):
        code = """
            result = session.execute(text("SELECT * FROM users WHERE name='%s'" % name))
        """
        assert fires(code, "ORM001"), "ORM001 must fire: %-format inside text()"

    def test_safe_parameterized_text_safe(self):
        code = """
            result = session.execute(text("SELECT * FROM users WHERE id = :uid"), {"uid": uid})
        """
        assert not_fires(code, "ORM001"), "ORM001 must NOT fire for static text() with params"


# ============================================================
# ORM002 — Django ORM injection (raw, order_by, extra)
# ============================================================

class TestORM002:
    def test_raw_tainted_sql_fires(self):
        code = """
            sql = request.GET.get('q')
            users = User.objects.raw(sql)
        """
        assert fires(code, "ORM002"), "ORM002 must fire: tainted SQL in raw()"

    def test_order_by_tainted_fires(self):
        code = """
            sort = request.GET.get('sort')
            qs = User.objects.order_by(sort)
        """
        assert fires(code, "ORM002"), "ORM002 must fire: tainted field in order_by (CVE-2021-35042)"

    def test_order_by_literal_safe(self):
        code = """
            qs = User.objects.order_by('username')
        """
        assert not_fires(code, "ORM002"), "ORM002 must NOT fire for literal field name in order_by"


# ============================================================
# DESER725 — jsonpickle deserialization
# ============================================================

class TestDESER725:
    def test_jsonpickle_decode_fires(self):
        code = "import jsonpickle; obj = jsonpickle.decode(data)"
        assert fires(code, "DESER725"), "DESER725 must fire: jsonpickle.decode"

    def test_comment_line_safe(self):
        code = "# jsonpickle.decode(data)"
        assert not_fires(code, "DESER725"), "DESER725 must NOT fire in comment"


# ============================================================
# DESER726 — dill deserialization
# ============================================================

class TestDESER726:
    def test_dill_loads_fires(self):
        code = "import dill; obj = dill.loads(payload)"
        assert fires(code, "DESER726"), "DESER726 must fire: dill.loads"

    def test_comment_line_safe(self):
        code = "# dill.loads(data)"
        assert not_fires(code, "DESER726"), "DESER726 must NOT fire in comment"


# ============================================================
# TLS001 — TLS verification disabled
# ============================================================

class TestTLS001:
    def test_verify_false_fires(self):
        code = "resp = requests.get(url, verify=False)"
        assert fires(code, "TLS001"), "TLS001 must fire: requests verify=False"

    def test_disable_warnings_fires(self):
        code = "urllib3.disable_warnings(InsecureRequestWarning)"
        assert fires(code, "TLS001"), "TLS001 must fire: disable_warnings InsecureRequestWarning"

    def test_verify_true_safe(self):
        code = "resp = requests.get(url, verify=True)"
        assert not_fires(code, "TLS001"), "TLS001 must NOT fire for verify=True"

    def test_verify_capath_safe(self):
        code = "resp = requests.get(url, verify='/etc/ssl/certs/ca-bundle.crt')"
        assert not_fires(code, "TLS001"), "TLS001 must NOT fire for verify=CA path"


# ============================================================
# SSH001 — Paramiko MITM
# ============================================================

class TestSSH001:
    def test_auto_add_policy_fires(self):
        code = "client.set_missing_host_key_policy(paramiko.AutoAddPolicy())"
        assert fires(code, "SSH001"), "SSH001 must fire: AutoAddPolicy()"

    def test_reject_policy_safe(self):
        code = "client.set_missing_host_key_policy(paramiko.RejectPolicy())"
        assert not_fires(code, "SSH001"), "SSH001 must NOT fire for RejectPolicy"


# ============================================================
# JWT001 — JWT signature bypass
# ============================================================

class TestJWT001:
    def test_verify_signature_false_fires(self):
        code = 'payload = jwt.decode(token, options={"verify_signature": False})'
        assert fires(code, "JWT001"), "JWT001 must fire: verify_signature=False"

    def test_algorithms_none_fires(self):
        code = "payload = jwt.decode(token, algorithms=['none'])"
        assert fires(code, "JWT001"), "JWT001 must fire: algorithms=['none']"

    def test_valid_decode_safe(self):
        code = "payload = jwt.decode(token, secret, algorithms=['HS256'])"
        assert not_fires(code, "JWT001"), "JWT001 must NOT fire for valid HS256 decode"


# ============================================================
# ZIPSLIP001 — Archive extraction without path validation
# ============================================================

class TestZIPSLIP001:
    def test_zipfile_extractall_fires(self):
        code = "zf.extractall('/var/app/uploads/')"
        assert fires(code, "ZIPSLIP001"), "ZIPSLIP001 must fire: zipfile extractall"

    def test_tarfile_extractall_fires(self):
        code = "tf.extractall('/tmp/extract/')"
        assert fires(code, "ZIPSLIP001"), "ZIPSLIP001 must fire: tarfile extractall"


# ============================================================
# XXE001 — lxml XXE
# ============================================================

class TestXXE001:
    def test_etree_parse_fires(self):
        code = "from lxml import etree; tree = etree.parse(user_file)"
        assert fires(code, "XXE001"), "XXE001 must fire: etree.parse without safe parser"

    def test_etree_fromstring_fires(self):
        code = "from lxml import etree; root = etree.fromstring(xml_data)"
        assert fires(code, "XXE001"), "XXE001 must fire: etree.fromstring"

    def test_defusedxml_safe(self):
        code = "from defusedxml import etree; root = etree.fromstring(xml_data)"
        assert not_fires(code, "XXE001"), "XXE001 must NOT fire when defusedxml is used"

    def test_resolve_entities_false_safe(self):
        code = "p = etree.XMLParser(resolve_entities=False); tree = etree.parse(f, p)"
        assert not_fires(code, "XXE001"), "XXE001 must NOT fire when resolve_entities=False"


# ============================================================
# FLASK001 — Flask debug mode
# ============================================================

class TestFLASK001:
    def test_app_run_debug_fires(self):
        code = "app.run(host='0.0.0.0', debug=True)"
        assert fires(code, "FLASK001"), "FLASK001 must fire: app.run(debug=True)"

    def test_app_debug_assignment_fires(self):
        code = "app.debug = True"
        assert fires(code, "FLASK001"), "FLASK001 must fire: app.debug = True"

    def test_debug_false_safe(self):
        code = "app.run(host='0.0.0.0', debug=False)"
        assert not_fires(code, "FLASK001"), "FLASK001 must NOT fire for debug=False"


# ============================================================
# FILE_WRITE001 — writing user content to files
# ============================================================

class TestFILE_WRITE001:
    # FILE_WRITE001 taint sink (SK_FILE_WRITE001) removed — write() is too generic.
    # It fired on HTTP response writes (response.write()), cache writes, and all
    # framework file operations generating massive FPs (74 in CPython, 24 in Django).
    # Rule remains for documentation; the finding in PyGoat is still detected via
    # the PLAIN_PWD001, FILE_WRITE001 pattern, and broader path traversal rules.
    def test_tainted_write_silent_disabled(self):
        code = """
            code = request.POST.get('code')
            f = open('/tmp/plugin.py', 'w')
            f.write(code)
        """
        assert not_fires(code, "FILE_WRITE001"), "FILE_WRITE001 taint sink disabled: write() too generic"

    def test_constant_write_safe(self):
        code = """
            f = open('/tmp/output.py', 'w')
            f.write('print("hello")')
        """
        assert not_fires(code, "FILE_WRITE001"), "FILE_WRITE001 must NOT fire for constant content"


# ============================================================
# OPEN_REDIRECT001 — unvalidated redirect URL
# ============================================================

class TestOPENREDIRECT001:
    def test_flask_redirect_fires(self):
        code = """
            next_url = request.GET.get('next')
            return redirect(next_url)
        """
        assert fires(code, "OPEN_REDIRECT001"), "OPEN_REDIRECT001 must fire: user-controlled redirect URL"

    def test_django_redirect_fires(self):
        code = """
            url = request.GET.get('url')
            return HttpResponseRedirect(url)
        """
        assert fires(code, "OPEN_REDIRECT001"), "OPEN_REDIRECT001 must fire: HttpResponseRedirect with user URL"

    def test_hardcoded_redirect_safe(self):
        code = """
            return redirect('/dashboard/')
        """
        assert not_fires(code, "OPEN_REDIRECT001"), "OPEN_REDIRECT001 must NOT fire for hardcoded redirect"


# ============================================================
# PLAIN_PWD001 — plaintext password in Django ORM create()
# ============================================================

class TestPLAINPWD001:
    def test_create_with_tainted_password_fires(self):
        code = """
            pwd = request.POST.get('password')
            User.objects.create(username='alice', password=pwd)
        """
        assert fires(code, "PLAIN_PWD001"), "PLAIN_PWD001 must fire: tainted password in ORM create()"

    def test_hashed_password_safe(self):
        code = """
            from django.contrib.auth.hashers import make_password
            User.objects.create(username='alice', password=make_password(raw_pwd))
        """
        assert not_fires(code, "PLAIN_PWD001"), "PLAIN_PWD001 must NOT fire when password is hashed"


# ============================================================
# DJANGO_DEBUG001 — DEBUG=True in settings
# ============================================================

class TestDJANGO_DEBUG001:
    def test_debug_true_fires(self):
        code = "DEBUG = True"
        assert fires(code, "DJANGO_DEBUG001"), "DJANGO_DEBUG001 must fire: DEBUG=True"

    def test_debug_false_safe(self):
        code = "DEBUG = False"
        assert not_fires(code, "DJANGO_DEBUG001"), "DJANGO_DEBUG001 must NOT fire for DEBUG=False"

    def test_debug_env_var_safe(self):
        code = "DEBUG = os.environ.get('DEBUG', 'False') == 'True'"
        assert not_fires(code, "DJANGO_DEBUG001"), "DJANGO_DEBUG001 must NOT fire for env var pattern"


# ============================================================
# PATH813 via os.path.join (new taint propagation)
# ============================================================

class TestOSPathJoinPropagation:
    def test_path_join_propagates_to_open(self):
        code = """
            blog = request.POST.get('blog')
            filename = os.path.join('/app/blogs', blog)
            f = open(filename, 'r')
        """
        assert fires(code, "OPEN1149"), "os.path.join must propagate taint to open() → OPEN1149"

    def test_imagmath_eval_via_sink(self):
        code = """
            from PIL import ImageMath, Image
            func = request.POST.get('function')
            img = Image.open('test.png')
            output = ImageMath.eval(func, img=img)
        """
        assert fires(code, "PY001"), "ImageMath.eval() must fire PY001 via SK_IMG_EVAL001 taint sink"


# ============================================================
# file_content_exclude — PY302/PY107 ruamel false positive fix
# ============================================================

class TestFileContentExclude:
    def test_pyyaml_unsafe_fires(self):
        # Plain PyYAML import with unsafe load — must fire
        code = "import yaml\nyaml.load(data)"
        assert fires(code, "PY302"), "PY302 must fire for PyYAML yaml.load() without Loader"

    def test_ruamel_yaml_suppressed(self, tmp_path):
        # ruamel.yaml with YAML() round-trip is safe — must NOT fire
        # file_content_exclude = "from ruamel.yaml|import ruamel" suppresses it
        from pyspector._rust_core import run_scan
        from pyspector.config import get_default_rules
        import ast as _ast, json as _json, os, warnings
        from pyspector.cli import AstEncoder

        code = "from ruamel.yaml import YAML\nyaml = YAML()\nyaml.load(stream)"
        filename = str(tmp_path / "settings.py")
        with open(filename, "w") as f:
            f.write(code)
        rules_toml = get_default_rules()
        tree = _ast.parse(code, filename=filename)
        ast_json = _json.dumps(_ast.dump(tree), cls=AstEncoder)
        files = [{"file_path": filename, "content": code, "ast_json": ast_json}]
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore")
            results = run_scan(str(tmp_path), rules_toml, {"exclude": []}, files)
        py302 = [r for r in results if r.rule_id in ("PY302", "PY107")]
        assert len(py302) == 0, f"PY302/PY107 must NOT fire for ruamel YAML() round-trip, got: {py302}"


# ============================================================
# CLI vs HTTP taint distinction (OperatorConfig vs HttpRequest)
# ============================================================

class TestCLIvsHTTPTaint:
    def test_http_path_fires_PATH813(self):
        # @app.route path param → HttpRequest → PATH813
        code = """
            path = request.GET.get('path')
            from pathlib import Path
            Path(path).mkdir(parents=True, exist_ok=True)
        """
        assert fires(code, "PATH813"), "HTTP path traversal must fire PATH813"

    def test_cli_path_no_PATH813(self):
        # @app.command path param → OperatorConfig → no PATH813
        code = """
            @app.command()
            def run(output):
                from pathlib import Path
                Path(output).mkdir(parents=True, exist_ok=True)
        """
        assert not_fires(code, "PATH813"), \
            "CLI operator path must NOT fire PATH813 — operator chose the path"

    def test_json_load_supply_chain_fires(self):
        # json.load is a FILE_DESERIALIZER: always produces HttpRequest taint
        # regardless of how the file path was obtained. Supply-chain detection
        # is preserved even when the operator chose the file path.
        code = """
            import json
            config_path = request.POST.get("config")
            data = json.load(open(config_path))
            f = open(data, "w")
        """
        assert fires(code, "OPEN1149"), \
            "json.load FILE_DESERIALIZER must propagate HttpRequest to open() sink"
