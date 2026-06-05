import sys
from pathlib import Path

import toml

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from pyspector.config import DEFAULT_CONFIG, get_default_rules, load_config


def test_load_config_merges_valid_pyspector_section(tmp_path):
    config_path = tmp_path / "pyspector.toml"
    config_path.write_text(
        """
[tool.pyspector]
severity = "HIGH"
exclude = ["custom"]
extra_setting = "kept"
""".strip(),
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config["severity"] == "HIGH"
    assert config["exclude"] == ["custom"]
    assert config["extra_setting"] == "kept"


def test_load_config_uses_defaults_when_file_is_missing(tmp_path):
    config = load_config(tmp_path / "missing.toml")

    assert config == DEFAULT_CONFIG
    assert config["severity"] == "LOW"
    assert "node_modules" in config["exclude"]
    assert "**/test_*.py" in config["exclude"]


def test_load_config_uses_defaults_for_invalid_toml(tmp_path, capsys):
    config_path = tmp_path / "pyspector.toml"
    config_path.write_text("[tool.pyspector\nseverity = 'HIGH'\n", encoding="utf-8")

    config = load_config(config_path)

    assert config == DEFAULT_CONFIG
    assert "Could not parse config file" in capsys.readouterr().out


def test_load_config_defaults_are_copied_before_user_updates(tmp_path):
    config_path = tmp_path / "pyspector.toml"
    config_path.write_text(
        """
[tool.pyspector]
severity = "MEDIUM"
""".strip(),
        encoding="utf-8",
    )

    config = load_config(config_path)
    config["exclude"].append("local-only")

    assert config["severity"] == "MEDIUM"
    assert "local-only" not in DEFAULT_CONFIG["exclude"]


def test_get_default_rules_loads_parseable_builtin_rules():
    rules = toml.loads(get_default_rules())

    rule_ids = {rule["id"] for rule in rules["rule"]}
    assert "PY001" in rule_ids
    assert "AI202" not in rule_ids


def test_get_default_rules_includes_ai_rules_when_enabled(capsys):
    rules = toml.loads(get_default_rules(ai_scan=True))

    rule_ids = {rule["id"] for rule in rules["rule"]}
    assert "PY001" in rule_ids
    assert "AI202" in rule_ids
    assert "AI scanning enabled" in capsys.readouterr().out


def test_get_default_rules_substitutes_shared_placeholder_regex():
    rules_text = get_default_rules(ai_scan=True)
    rules = toml.loads(rules_text)

    placeholder = rules["defaults"]["exclude_pattern_placeholder"]
    assert "__SHARED_PLACEHOLDERS__" not in rules_text
    assert placeholder

    placeholder_backed_rules = [
        rule for rule in rules["rule"] if rule.get("exclude_pattern") == placeholder
    ]
    assert placeholder_backed_rules
