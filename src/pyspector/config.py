import re
from pathlib import Path
import toml # type: ignore
import click # type: ignore
try:
    # Python 3.9+
    import importlib.resources as pkg_resources
except ImportError:
    # Fallback for older Python versions
    import importlib_resources as pkg_resources # type: ignore

# Sentinel placed inside any rule's `exclude_pattern` to inherit the shared
# placeholder regex declared at [defaults].exclude_pattern_placeholder. The
# sentinel is string-substituted in `get_default_rules` before the TOML text
# is handed to the Rust core.
_PLACEHOLDER_SENTINEL = "__SHARED_PLACEHOLDERS__"
_PLACEHOLDER_KEY_RX = re.compile(
    r'^\s*exclude_pattern_placeholder\s*=\s*"((?:[^"\\]|\\.)*)"',
    re.MULTILINE,
)

DEFAULT_CONFIG = {
    "exclude": [
        ".venv", "venv", ".git", "__pycache__", "build", "dist", "*.egg-info",
        # Dependency / vendored directories
        "node_modules", "bower_components", "vendor",
        # Add test fixture exclusions
        "*/tests/fixtures/*",
        "*/test/fixtures/*",
        "*_fixtures/*",
        "*/testdata/*",
        # Common test file patterns with intentionally bad syntax
        "**/test_*.py",
        "**/*_test.py",
    ],
    "severity": "LOW",
}

# Default Shannon-entropy threshold (bits/char) for the generic high-entropy
# secret rule. Can be overridden via `[tool.pyspector.secrets] entropy_threshold`
# in the config file, or the `--entropy-threshold` CLI flag.
DEFAULT_ENTROPY_THRESHOLD = 4.5

def load_config(config_path: Path) -> dict:
    """Loads configuration from a TOML file or returns defaults.

    A `[tool.pyspector.secrets]` sub-table (if present) is merged into the
    returned config: its `entropy_threshold` overrides the top-level
    `entropy_threshold` key (read directly by the Rust scan engine), and its
    `exclude` list is appended to the main exclude list.
    """
    config = DEFAULT_CONFIG.copy()
    config["entropy_threshold"] = DEFAULT_ENTROPY_THRESHOLD

    if config_path and config_path.exists():
        try:
            with config_path.open('r') as f:
                user_config = toml.load(f).get('tool', {}).get('pyspector', {})
                secrets_config = user_config.pop('secrets', {}) if isinstance(user_config, dict) else {}

                config.update(user_config)

                if 'entropy_threshold' in secrets_config:
                    config['entropy_threshold'] = secrets_config['entropy_threshold']
                if 'exclude' in secrets_config:
                    config['exclude'] = list(config.get('exclude', [])) + list(secrets_config['exclude'])

                return config
        except Exception as e:
            click.echo(click.style(f"Warning: Could not parse config file '{config_path}'. Using defaults. Error: {e}", fg="yellow"))
    return config

def get_default_rules(ai_scan: bool = False, secrets_scan: bool = False) -> str:
    """Loads the built-in TOML rules file from package resources.

    Substitutes the `__SHARED_PLACEHOLDERS__` sentinel inside any rule's
    exclude_pattern with the value of `[defaults].exclude_pattern_placeholder`,
    so the placeholder/dummy-secret regex lives in one place rather than being
    copy-pasted across every format-specific rule.

    When `secrets_scan` is True, only the secret-detection ruleset is
    returned (not the main/AI rulesets): secret scans skip Python AST parsing
    entirely and only need regex + entropy rules, so keeping the ruleset
    focused avoids unrelated noise and keeps the scan fast.
    """
    try:
        if secrets_scan:
            return pkg_resources.files('pyspector.rules').joinpath('built-in-rules-secrets.toml').read_text(encoding='utf-8')

        base_rules = pkg_resources.files('pyspector.rules').joinpath('built-in-rules.toml').read_text(encoding='utf-8')
        if ai_scan:
            click.echo("[*] AI scanning enabled. Loading additional AI/LLM rules.")
            ai_rules = pkg_resources.files('pyspector.rules').joinpath('built-in-rules-ai.toml').read_text(encoding='utf-8')
            text = base_rules + "\n" + ai_rules
        else:
            text = base_rules

        # Inline shared placeholder regex into rule-level exclude_patterns
        m = _PLACEHOLDER_KEY_RX.search(text)
        if m and _PLACEHOLDER_SENTINEL in text:
            text = text.replace(_PLACEHOLDER_SENTINEL, m.group(1))
        return text
    except Exception as e:
        raise FileNotFoundError(f"Could not load built-in rules from package data! Error: {e}")
