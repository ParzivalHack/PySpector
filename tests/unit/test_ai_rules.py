import ast
import json
import os
import re
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


def _ai_rule(rule_id: str) -> dict:
    rules = toml.loads(RULES_PATH.read_text(encoding="utf-8"))
    return next(rule for rule in rules["rule"] if rule["id"] == rule_id)


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
        rule = _ai_rule("AI206")
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
        rule = _ai_rule("AI204")
        assert re.search(rule["pattern"], "model = joblib.load(model_path)")
        assert not re.search(rule["exclude_pattern"], "model = joblib.load(model_path)")

    def test_commented_joblib_model_load_safe(self):
        rule = _ai_rule("AI204")
        code = "# model = joblib.load(model_path)"
        assert re.search(rule["pattern"], code)
        assert re.search(rule["exclude_pattern"], code)
class TestAI202:
    def test_rule_metadata(self):
        rule = _ai_rule("AI202")
        assert rule["severity"] == "High"
        assert rule["cwe"] == "CWE-502"
        assert rule["pattern"] == r"torch\.load\s*\("
        assert rule["exclude_pattern"] == r"^\s*#|weights_only\s*=\s*True"

    @pytest.mark.parametrize(
        "code",
        [
            'model = torch.load("model.pt")',
            "checkpoint = torch.load(path, map_location='cpu')",
        ],
    )
    def test_pattern_matches_torch_load_calls(self, code):
        rule = _ai_rule("AI202")
        assert re.search(rule["pattern"], code)
        assert not re.search(rule["exclude_pattern"], code)

    @pytest.mark.parametrize(
        "code",
        [
            '# model = torch.load("model.pt")',
            'model = torch.load("model.pt", weights_only=True)',
            'model = torch.load("model.pt", weights_only = True)',
        ],
    )
    def test_exclude_pattern_suppresses_safe_or_comment_cases(self, code):
        rule = _ai_rule("AI202")
        assert re.search(rule["pattern"], code)
        assert re.search(rule["exclude_pattern"], code)


# -------------------------------------------
# Tests for AI600 - Unsafe Agent Behavior
# -------------------------------------------

class TestAI600AgentBehavior:
    def test_ai601_removed_covered_by_ai501_taint(self):
        rule_ids = [rule["id"] for rule in toml.loads(RULES_PATH.read_text(encoding="utf-8"))["rule"]]
        assert "AI601" not in rule_ids

    def test_ai601_removed_taint_flow_fires_ai501_not_ai601(self):
        code = """
            url = input("target: ")
            requests.get(url)
        """
        results = run_pyspector_ai(code)
        assert any(result["rule_id"] == "AI501" for result in results)
        assert not any(result["rule_id"] == "AI601" for result in results)

    def test_ai601_removed_trusted_url_not_tainted(self):
        code = """
            response = requests.get("https://api.example.com/data")
        """
        assert not fires(code, "AI501")

    def test_ai501_multiline_requests_get_taint(self):
        code = """
            url = input("target: ")
            requests.get(
                url,
                headers={"User-Agent": "agent"},
            )
        """
        assert fires(code, "AI501")

    def test_ai501_tainted_url_from_request_body(self):
        code = """
            url = request.form.get("url")
            requests.get(url)
        """
        assert fires(code, "AI501")

    def test_aits11_chroma_retrieval_taint_flow(self):
        code = """
            docs = vectorstore.similarity_search(user_query)
            prompt = langchain.prompts.PromptTemplate.from_template(docs[0].page_content)
        """
        assert fires(code, "AI101")

    def test_aits11_no_retrieval_no_taint(self):
        code = """
            docs = [{"page_content": user_query}]
            prompt = langchain.prompts.PromptTemplate.from_template(docs[0]["page_content"])
        """
        assert not fires(code, "AI101")

    def test_ai602_metadata(self):
        rule = _ai_rule("AI602")
        assert rule["severity"] == "Critical"
        assert rule["cwe"] == "CWE-78"

    def test_ai602_pattern_matches_shell_true(self):
        rule = _ai_rule("AI602")
        assert re.search(rule["pattern"], "subprocess.run(command, shell=True)")

    def test_ai602_shell_false_is_safe(self):
        code = """
            subprocess.run(["python", "-m", "pytest"])
        """
        assert not fires(code, "AI602")

    def test_ai603_removed(self):
        rule_ids = [rule["id"] for rule in toml.loads(RULES_PATH.read_text(encoding="utf-8"))["rule"]]
        assert "AI603" not in rule_ids

    def test_ai604_removed(self):
        rule_ids = [rule["id"] for rule in toml.loads(RULES_PATH.read_text(encoding="utf-8"))["rule"]]
        assert "AI604" not in rule_ids

    def test_ai605_metadata(self):
        rule = _ai_rule("AI605")
        assert rule["severity"] == "Medium"
        assert rule["cwe"] == "CWE-200"

    def test_ai605_pattern_matches(self):
        rule = _ai_rule("AI605")
        assert re.search(rule["pattern"], "agent = initialize_agent(verbose=True)")

    def test_ai605_verbose_false_is_safe(self):
        code = """
            agent = initialize_agent(verbose=False)
        """
        assert not fires(code, "AI605")

    def test_ai606_metadata(self):
        rule = _ai_rule("AI606")
        assert rule["severity"] == "Medium"
        assert rule["cwe"] == "CWE-209"

    def test_ai606_pattern_matches(self):
        rule = _ai_rule("AI606")
        assert re.search(rule["pattern"], "agent = initialize_agent(handle_parsing_errors=False)")


# -------------------------------------------
# Tests for AI700 - RAG Security
# -------------------------------------------

class TestAI700RAGSecurity:
    def test_ai701_metadata(self):
        rule = _ai_rule("AI701")
        assert rule["severity"] == "High"
        assert rule["cwe"] == "CWE-345"

    def test_ai701_pattern_matches(self):
        rule = _ai_rule("AI701")
        assert re.search(rule["pattern"], "loader = DirectoryLoader('./docs')")

    def test_ai701_plain_file_read_is_safe(self):
        code = """
            content = Path("./data.txt").read_text()
        """
        assert not fires(code, "AI701")

    def test_ai702_metadata(self):
        rule = _ai_rule("AI702")
        assert rule["severity"] == "Medium"
        assert rule["cwe"] == "CWE-20"

    def test_ai702_pattern_matches_score_threshold(self):
        rule = _ai_rule("AI702")
        assert re.search(rule["pattern"], "docs = vectorstore.similarity_search(query, score_threshold=0.3)")

    def test_ai702_top_k_without_threshold_is_safe(self):
        code = """
            docs = vectorstore.similarity_search(query, k=4)
        """
        assert not fires(code, "AI702")

    def test_ai703_metadata(self):
        rule = _ai_rule("AI703")
        assert rule["severity"] == "Medium"
        assert rule["cwe"] == "CWE-400"

    def test_ai703_pattern_matches(self):
        rule = _ai_rule("AI703")
        assert re.search(rule["pattern"], "chain = combine_docs(llm, docs)")

    def test_ai703_plain_context_join_is_safe(self):
        code = """
            context = "\\n".join(docs)
        """
        assert not fires(code, "AI703")

    def test_ai704_metadata(self):
        rule = _ai_rule("AI704")
        assert rule["severity"] == "High"
        assert rule["cwe"] == "CWE-345"

    def test_ai704_pattern_matches(self):
        rule = _ai_rule("AI704")
        assert re.search(rule["pattern"], "embeddings = HuggingFaceEmbeddings(model_name='all-MiniLM-L6-v2')")

    def test_ai704_other_embedding_model_is_safe(self):
        code = """
            embeddings = OpenAIEmbeddings(model="text-embedding-3-small")
        """
        assert not fires(code, "AI704")


# -------------------------------------------
# Tests for AI800 - API Key Management
# -------------------------------------------

class TestAI800APIKeyManagement:
    def test_ai801_metadata(self):
        rule = _ai_rule("AI801")
        assert rule["severity"] == "Critical"
        assert rule["cwe"] == "CWE-798"

    def test_ai801_pattern_matches(self):
        rule = _ai_rule("AI801")
        assert re.search(rule["pattern"], 'openai.api_key = "sk-abc123def456"')

    def test_ai801_pattern_no_match_env_var(self):
        rule = _ai_rule("AI801")
        assert not re.search(rule["pattern"], 'openai.api_key = os.getenv("OPENAI_API_KEY")')

    def test_ai802_metadata(self):
        rule = _ai_rule("AI802")
        assert rule["severity"] == "Critical"
        assert rule["cwe"] == "CWE-798"

    def test_ai802_pattern_matches(self):
        rule = _ai_rule("AI802")
        assert re.search(rule["pattern"], 'anthropic.api_key = "sk-ant-abc123"')

    def test_ai803_metadata(self):
        rule = _ai_rule("AI803")
        assert rule["severity"] == "High"
        assert rule["cwe"] == "CWE-598"

    def test_ai804_metadata(self):
        rule = _ai_rule("AI804")
        assert rule["severity"] == "Critical"
        assert rule["cwe"] == "CWE-798"

    def test_ai804_pattern_matches(self):
        rule = _ai_rule("AI804")
        assert re.search(rule["pattern"], "cohere.Client(api_key='abc123')")


# -------------------------------------------
# Tests for AI900 - Output Handling & DoS
# -------------------------------------------

class TestAI900OutputHandling:
    def test_ai901_metadata(self):
        rule = _ai_rule("AI901")
        assert rule["severity"] == "Critical"
        assert rule["cwe"] == "CWE-502"

    def test_ai901_pattern_matches(self):
        rule = _ai_rule("AI901")
        assert re.search(rule["pattern"], "data = yaml.load(llm_output)")

    def test_ai901_excludes_safe_load(self):
        rule = _ai_rule("AI901")
        code = "data = yaml.safe_load(llm_output)"
        assert not re.search(rule["pattern"], code)
        assert re.search(rule["exclude_pattern"], code)

    def test_ai901_pattern_requires_plain_load(self):
        rule = _ai_rule("AI901")
        assert re.search(rule["pattern"], "data = yaml.load(llm_output, Loader=yaml.FullLoader)")

    def test_ai902_metadata(self):
        rule = _ai_rule("AI902")
        assert rule["severity"] == "Medium"
        assert rule["cwe"] == "CWE-400"

    def test_ai902_pattern_matches_llm_output_variable(self):
        rule = _ai_rule("AI902")
        assert re.search(rule["pattern"], "data = json.loads(output)")

    def test_ai902_plain_json_parse_is_safe(self):
        code = """
            data = json.loads(request_body)
        """
        assert not fires(code, "AI902")

    def test_ai903_metadata(self):
        rule = _ai_rule("AI903")
        assert rule["severity"] == "Critical"
        assert rule["cwe"] == "CWE-94"

    def test_ai903_pattern_matches_eval_of_llm_output(self):
        rule = _ai_rule("AI903")
        assert re.search(rule["pattern"], "result = eval(llm_output)")

    def test_ai903_plain_eval_is_safe(self):
        code = """
            result = eval(expr)
        """
        assert not fires(code, "AI903")

    def test_ai903_response_variable_line_is_safe(self):
        code = """
            response = fetch_data()
            print(response)
        """
        assert not fires(code, "AI903")

    def test_ai904_metadata(self):
        rule = _ai_rule("AI904")
        assert rule["severity"] == "High"
        assert rule["cwe"] == "CWE-79"

    def test_ai904_pattern_matches_inner_html(self):
        rule = _ai_rule("AI904")
        assert re.search(rule["pattern"], "element.innerHTML = llm_reply")
        assert not re.search(rule["exclude_pattern"], "element.innerHTML = llm_reply")

    def test_ai904_sanitized_inner_html_is_safe(self):
        code = """
            element.innerHTML = sanitize_html(llm_reply)
        """
        assert not fires(code, "AI904")

    def test_ai904_response_variable_line_is_safe(self):
        code = """
            response = render_template("index.html", data=data)
        """
        assert not fires(code, "AI904")
