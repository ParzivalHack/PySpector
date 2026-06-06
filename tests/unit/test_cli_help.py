import sys
import types

from click.testing import CliRunner

rust_core = types.ModuleType("pyspector._rust_core")
rust_core.run_scan = lambda *args, **kwargs: []
sys.modules.setdefault("pyspector._rust_core", rust_core)

from pyspector.cli import cli  # noqa: E402


def test_root_help_includes_scan_arguments_and_options():
    result = CliRunner().invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "Scan arguments and options" in result.output
    assert "PATH" in result.output

    expected_scan_flags = [
        "--url",
        "--config",
        "--output",
        "--format",
        "--severity",
        "--ai",
        "--plugin",
        "--plugin-config",
        "--list-plugins",
        "--supply-chain",
        "--syntax-warnings",
        "--wizard",
        "--stats",
        "--debug",
    ]
    for flag in expected_scan_flags:
        assert flag in result.output


def test_root_help_keeps_command_list():
    result = CliRunner().invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "Commands:" in result.output
    for command in ("scan", "triage", "watch", "plugin"):
        assert command in result.output
