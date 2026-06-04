import ast
import json
import os
import sys
import tempfile
import textwrap
import warnings
from pathlib import Path

import pytest
import toml

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

RULES_PATH = Path(__file__).parent.parent.parent / "src/pyspector/rules/built-in-rules-ai.toml"
AI206_MATCHER = (
    "Call(func.attr=from_pretrained, keywords.*.arg=trust_remote_code, "
    "keywords.*.value.value=True)"
)


def _wrap(code: str) -> str:
    indented = "\n".join("    " + line for line in textwrap.dedent(code).splitlines())
    return f"def _load_model():\n{indented}\n"


def _ai206_rule() -> dict:
    rules = toml.loads(RULES_PATH.read_text(encoding="utf-8"))
    return next(rule for rule in rules["rule"] if rule["id"] == "AI206")


def _ai_rule(rule_id: str) -> dict:
    rules = toml.loads(RULES_PATH.read_text(encoding="utf-8"))
    return next(rule for rule in rules["rule"] if rule["id"] == rule_id)


def _ast_node(node: ast.AST) -> dict:
    children = {}
    fields = {}
    for field, value in ast.iter_fields(node):
        if isinstance(value, list):
            if value and all(isinstance(item, ast.AST) for item in value):
                children[field] = [_ast_node(item) for item in value]
            else:
                fields[field] = str(value) if value else []
        elif isinstance(value, ast.AST):
            children[field] = [_ast_node(value)]
        else:
            fields[field] = value if isinstance(value, (int, float, str, bool)) or value is None else str(value)
    return {"node_type": node.__class__.__name__, "children": children, "fields": fields}


def _has_property(node: dict, path: list[str], expected: str) -> bool:
    if not path:
        return False
    current, remaining = path[0], path[1:]
    if not remaining and current in node["fields"]:
        value = node["fields"][current]
        if isinstance(value, bool):
            return str(value).lower() == expected.lower()
        return str(value) == expected
    if current in node["children"]:
        if remaining and remaining[0] == "*":
            return any(_has_property(child, remaining[1:], expected) for child in node["children"][current])
        if remaining and node["children"][current]:
            return _has_property(node["children"][current][0], remaining, expected)
    return False


def _matches_ai206(code: str) -> bool:
    node = _ast_node(ast.parse(code).body[0].value)
    node_type, props = AI206_MATCHER.split("(", 1)
    props = props.rsplit(")", 1)[0]
    return node["node_type"] == node_type and all(
        _has_property(node, path.strip().split("."), expected)
        for path, expected in (part.strip().split("=", 1) for part in props.split(","))
    )


def run_pyspector_ai(code: str, filename: str = "model_loader.py") -> list[dict]:
    try:
        from pyspector._rust_core import run_scan
        from pyspector.cli import AstEncoder
        from pyspector.config import get_default_rules
    except (ImportError, SystemExit) as exc:
        pytest.skip(f"PySpector Rust core is not available: {exc}")

    wrapped = _wrap(code)
    rules_toml = get_default_rules(ai_scan=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, filename)
        Path(path).write_text(wrapped)
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore")
            try:
                ast_json = json.dumps(ast.parse(wrapped), cls=AstEncoder)
            except Exception:
                ast_json = "{}"
        files = [{"file_path": filename, "content": wrapped, "ast_json": ast_json}]
        results = run_scan(tmpdir, rules_toml, {"exclude": []}, files)

    return [{"rule_id": result.rule_id, "line_number": result.line_number} for result in results]


def fires(code: str, rule_id: str) -> bool:
    return any(result["rule_id"] == rule_id for result in run_pyspector_ai(code))


class TestAI206:
    def test_rule_metadata(self):
        rule = _ai206_rule()
        assert rule["severity"] == "High"
        assert rule["cwe"] == "CWE-94"
        assert rule["ast_match"] == AI206_MATCHER

    def test_matcher_targets_true_keyword_only(self):
        true_code = 'AutoModelForCausalLM.from_pretrained("example/model", trust_remote_code=True)'
        false_code = 'AutoModelForCausalLM.from_pretrained("example/model", trust_remote_code=False)'
        assert _matches_ai206(true_code)
        assert not _matches_ai206(false_code)

    def test_trust_remote_code_true_fires(self):
        code = """
            model = AutoModelForCausalLM.from_pretrained(
                "example/model",
                trust_remote_code=True,
            )
        """
        assert fires(code, "AI206")

    def test_trust_remote_code_false_safe(self):
        code = """
            model = AutoModelForCausalLM.from_pretrained(
                "example/model",
                trust_remote_code=False,
            )
        """
        assert not fires(code, "AI206")


class TestAIModelDeserializationPatterns:
    def test_keras_h5_model_load_metadata(self):
        rule = _ai_rule("AI203")
        assert rule["severity"] == "High"
        assert rule["cwe"] == "CWE-502"
        assert rule["pattern"] == r"keras\.models\.load_model"

    def test_keras_h5_model_load_fires(self):
        code = """
            model = keras.models.load_model(model_path)
        """
        assert fires(code, "AI203")

    def test_commented_keras_h5_model_load_safe(self):
        code = """
            # model = keras.models.load_model(model_path)
        """
        assert not fires(code, "AI203")

    def test_joblib_model_load_metadata(self):
        rule = _ai_rule("AI204")
        assert rule["severity"] == "High"
        assert rule["cwe"] == "CWE-502"
        assert rule["pattern"] == r"joblib\.load"

    def test_joblib_model_load_fires(self):
        code = """
            model = joblib.load(model_path)
        """
        assert fires(code, "AI204")

    def test_commented_joblib_model_load_safe(self):
        code = """
            # model = joblib.load(model_path)
        """
        assert not fires(code, "AI204")
