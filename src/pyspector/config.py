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

def load_config(config_path: Path) -> dict:
    """Loads configuration from a TOML file or returns defaults."""
    if config_path and config_path.exists():
        try:
            with config_path.open('r') as f:
                user_config = toml.load(f).get('tool', {}).get('pyspector', {})
                config = DEFAULT_CONFIG.copy()
                config.update(user_config)
                return config
        except Exception as e:
            click.echo(click.style(f"Warning: Could not parse config file '{config_path}'. Using defaults. Error: {e}", fg="yellow"))
    return DEFAULT_CONFIG

def get_default_rules(ai_scan: bool = False) -> str:
    """Loads the built-in TOML rules file from package resources.

    Substitutes the `__SHARED_PLACEHOLDERS__` sentinel inside any rule's
    exclude_pattern with the value of `[defaults].exclude_pattern_placeholder`,
    so the placeholder/dummy-secret regex lives in one place rather than being
    copy-pasted across every format-specific rule.
    """
    try:
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
        raise FileNotFoundError(f"Could not load built-in-rules.toml from package data! Error: {e}")
