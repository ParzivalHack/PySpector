from pathlib import Path
import toml # type: ignore
import click # type: ignore
try:
    # Python 3.9+
    import importlib.resources as pkg_resources
except ImportError:
    # Fallback for older Python versions
    import importlib_resources as pkg_resources # type: ignore

DEFAULT_CONFIG = {
    "exclude": [
        ".venv", "venv", ".git", "__pycache__", "build", "dist", "*.egg-info",
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
    """Loads the built-in TOML rules file from package resources."""
    try:
        base_rules = pkg_resources.files('pyspector.rules').joinpath('built-in-rules.toml').read_text(encoding='utf-8')
        if ai_scan:
            click.echo("[*] AI scanning enabled. Loading additional AI/LLM rules.")
            ai_rules = pkg_resources.files('pyspector.rules').joinpath('built-in-rules-ai.toml').read_text(encoding='utf-8')
            # Combine the two rulesets
            return base_rules + "\n" + ai_rules
        return base_rules
    except Exception as e:
        raise FileNotFoundError(f"Could not load built-in-rules.toml from package data! Error: {e}")
