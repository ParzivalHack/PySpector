from __future__ import annotations
import click
import time
import json
import ast
import subprocess
import tempfile
import sys
import warnings
from pathlib import Path
from typing import Optional, Dict, Any, List, cast

from .config import load_config, get_default_rules
from .reporting import Reporter
from .triage import run_triage_tui
from .plugin_system import get_plugin_manager, PluginSecurity
from .stats import StatsCollector
import requests
from urllib.parse import urlparse

# Import the Rust core from its new location
try:
    from pyspector._rust_core import run_scan
except ImportError:
    click.echo(click.style("Error: PySpector's core engine module not found.", fg="red"))
    exit(1)

import random

def get_startup_note():
    """Fetches a tech joke or returns a fallback if offline."""
    fallbacks = [
        "💡 'To err is human, to complain is even more human.'",
        "💡 There are 10 types of people: those who understand binary and those who don't.",
        "💡 A SQL query walks into a bar, walks up to two tables, and asks... 'Can I join you?'",
        "💡 Cybersecurity is the only industry where the 'bad guys' have a better R&D budget.",
        "💡 Hardware: The parts of a computer system that can be kicked."
    ]
    try:
        url = "https://v2.jokeapi.dev/joke/Programming?safe-mode&type=single"
        response = requests.get(url, timeout=1.5)
        if response.status_code == 200:
            return f"💡 {response.json()['joke']}"
    except Exception:
        pass
    return random.choice(fallbacks)

_list = list
_tuple = tuple
_ast_AST = ast.AST
_ast_iter_fields = ast.iter_fields

# --- Helper function for AST serialization ---
class AstEncoder(json.JSONEncoder):
    def default(self, node):
        if isinstance(node, _ast_AST):
            fields = {
                "node_type": node.__class__.__name__,
                "lineno": getattr(node, 'lineno', -1),
                "col_offset": getattr(node, 'col_offset', -1),
            }
            child_nodes = {}
            simple_fields = {}
            for field, value in _ast_iter_fields(node):
                if type(value).__name__ == 'list':
                    if value and all(isinstance(n, _ast_AST) for n in value):
                        child_nodes[field] = value
                    else:
                        simple_fields[field] = str(value) if value else []
                elif isinstance(value, _ast_AST):
                    child_nodes[field] = [value]
                else:
                    if isinstance(value, bytes):
                        simple_fields[field] = value.decode('utf-8', errors='replace')
                    elif isinstance(value, int) and value.bit_length() > 14000:
                        simple_fields[field] = 0
                    elif isinstance(value, (int, float, str, bool)) or value is None:
                        simple_fields[field] = value
                    else:
                        simple_fields[field] = str(value)

            fields["children"] = child_nodes
            fields["fields"] = simple_fields
            return fields
        elif isinstance(node, bytes):
            return node.decode('utf-8', errors='replace')
        elif hasattr(node, '__dict__'):
            return str(node)
        return super().default(node)


def should_skip_file(file_path: Path) -> bool:
    """Determine if a file should be skipped during AST parsing."""
    path_str = str(file_path)
    skip_patterns = [
        '/tests/fixtures/',
        '/test/fixtures/',
        '/testdata/',
        '/_fixtures/',
        '/fixtures/',
    ]
    for pattern in skip_patterns:
        if pattern in path_str.replace('\\', '/'):
            return True
    filename = file_path.name
    if filename.startswith('test_') or filename.endswith('_test.py'):
        if '/tests/' in path_str.replace('\\', '/') or '/test/' in path_str.replace('\\', '/'):
            return True
    return False


def get_python_file_asts(
    path: Path,
    enable_syntax_warnings: bool = False,
    _stats_meta: Optional[Dict[str, int]] = None,
) -> List[Dict[str, Any]]:
    """
    Recursively finds Python files and returns their content and AST.

    Args:
        path: File or directory to scan.
        enable_syntax_warnings: When True, SyntaxWarning is treated as an
            error and the offending file is excluded from results.
        _stats_meta: Optional dict that will be populated with
            ``{'skipped': N, 'errors': N}`` for use by StatsCollector.
            Defaults to None (no tracking).  Backward-compatible: callers
            that do not pass this argument are unaffected.
    """
    if _stats_meta is not None:
        _stats_meta['skipped'] = 0
        _stats_meta['errors']  = 0

    results = []
    files_to_scan = list(path.glob("**/*.py")) if path.is_dir() else [path]

    with warnings.catch_warnings():
        if not enable_syntax_warnings:
            warnings.filterwarnings('ignore', category=SyntaxWarning)
        else:
            warnings.filterwarnings('error', category=SyntaxWarning)

        for py_file in files_to_scan:
            if py_file.is_file():
                display_path = (
                    py_file.relative_to(path) if path.is_dir() else py_file.name
                )

                if should_skip_file(py_file):
                    click.echo(
                        click.style(
                            f"Info: Skipped {display_path} (test file or fixture)",
                            fg="blue",
                        )
                    )
                    if _stats_meta is not None:
                        _stats_meta['skipped'] += 1
                    continue

                try:
                    content = py_file.read_text(encoding="utf-8")
                    parsed_ast = ast.parse(content, filename=str(py_file))
                    ast_json = json.dumps(parsed_ast, cls=AstEncoder)
                    results.append(
                        {
                            "file_path": str(display_path),
                            "content": content,
                            "ast_json": ast_json,
                        }
                    )
                except SyntaxWarning as e:
                    click.echo(
                        click.style(
                            f"SyntaxWarning: there is a syntax warning in "
                            f"{display_path} - {e.msg} (line {e.lineno})",
                            fg="yellow",
                        )
                    )
                    if _stats_meta is not None:
                        _stats_meta['errors'] += 1
                except SyntaxError as e:
                    click.echo(
                        click.style(
                            f"SyntaxError: Could not parse {display_path} "
                            f"- {e.msg} (line {e.lineno})",
                            fg="red",
                        )
                    )
                    if _stats_meta is not None:
                        _stats_meta['errors'] += 1
                except UnicodeDecodeError as e:
                    click.echo(
                        click.style(
                            f"Warning: Could not read {display_path} "
                            f"- Invalid UTF-8 encoding ({e.reason})",
                            fg="yellow",
                        )
                    )
                    if _stats_meta is not None:
                        _stats_meta['errors'] += 1
                except Exception as e:
                    click.echo(
                        click.style(
                            f"Warning: Could not read {display_path} - {e}",
                            fg="yellow",
                        )
                    )
                    if _stats_meta is not None:
                        _stats_meta['errors'] += 1

    return results


def _normalize_plugin_name_cli(raw_name: str) -> tuple[str, bool]:
    """Normalise plugin identifiers for CLI usage."""
    stripped = raw_name.strip()
    normalised = stripped.replace("-", "_")
    if not normalised:
        raise click.ClickException("Plugin name cannot be empty.")
    if not normalised.isidentifier():
        raise click.ClickException(
            "Plugin names must be valid Python identifiers "
            "(letters, numbers, underscores)."
        )
    return normalised, normalised != stripped


def execute_plugins(
    findings: list,
    scan_path: Path,
    plugin_names: list,
    plugin_config: dict | None = None,
):
    """Execute specified plugins on scan results."""
    if not plugin_names:
        return

    click.echo(f"\n[*] Loading {len(plugin_names)} plugin(s)...")

    plugin_manager = get_plugin_manager()
    plugin_config = plugin_config or {}

    for plugin_name in plugin_names:
        plugin = plugin_manager.load_plugin(
            plugin_name,
            require_trusted=True,
            force_load=False,
        )

        if not plugin:
            click.echo(
                click.style(
                    f"[!] Failed to load plugin: {plugin_name}",
                    fg="yellow",
                )
            )
            continue

        config = plugin_config.get(plugin_name, {})
        original_argv = sys.argv.copy()
        sys.argv = [original_argv[0] if original_argv else "pyspector"]

        try:
            result = plugin_manager.execute_plugin(
                plugin,
                findings,
                scan_path,
                config,
            )
        finally:
            sys.argv = original_argv

        if result.get("success"):
            click.echo(
                click.style(
                    f"[+] {plugin.metadata.name}: {result.get('message', 'Success')}",
                    fg="green",
                )
            )
            if result.get("output_files"):
                click.echo("[*] Generated files:")
                for file_path in result["output_files"]:
                    click.echo(f"    - {file_path}")
        else:
            click.echo(
                click.style(
                    f"[!] {plugin.metadata.name}: {result.get('message', 'Failed')}",
                    fg="red",
                )
            )


# --- Main CLI Logic ---

@click.group()
def cli():
    """
    PySpector: A high-performance, security-focused static analysis tool
    for Python, powered by Rust.
    """
    banner = r"""
  o__ __o                   o__ __o                                         o                             
 <|     v\                 /v     v\                                       <|>                            
 / \     <\               />       <\                                      < >                            
 \o/     o/   o      o   _\o____        \o_ __o      o__  __o       __o__   |        o__ __o    \o__ __o  
  |__  _<|/  <|>    <|>       \_\__o__   |    v\    /v      |>     />  \    o__/_   /v     v\    |     |> 
  |          < >    < >             \   / \    <\  />      //    o/         |      />       <\  / \   < > 
 <o>          \o    o/    \         /   \o/     /  \o    o/     <|          |      \         /  \o/       
  |            v\  /v      o       o     |     o    v\  /v __o   \\         o       o       o    |        
 / \            <\/>       <\__ __/>    / \ __/>     <\/> __/>    _\o__</   <\__    <\__ __/>   / \       
                 /                      \o/                                                               
                o                        |                                                                
             __/>                       / \                                                                   
"""
    click.echo(click.style(banner))
    click.echo("Version: 0.1.8\n")
    click.echo("Made with <3 by github.com/ParzivalHack\n")
    note = get_startup_note()
    click.echo(click.style(f"{note}\n", fg="bright_black", italic=True))


def run_wizard():
    click.echo("\n🧙 PySpector Scan Wizard\n")

    mode = click.prompt(
        "What do you want to scan?",
        type=click.Choice(["local", "repo"]),
        default="local"
    )

    scan_path = None
    repo_url = None

    if mode == "local":
        scan_path = Path(click.prompt("Path to file or directory", type=str))
    else:
        repo_url = click.prompt("GitHub/GitLab repository URL", type=str)

    ai_scan = click.confirm("Enable AI / LLM vulnerability scanning?", default=False)

    severity_level = click.prompt(
        "Minimum severity level",
        type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
        default="LOW"
    )

    report_format = click.prompt(
        "Report format",
        type=click.Choice(["console", "json", "sarif", "html"]),
        default="console"
    )

    supply_chain = click.confirm("Check dependencies for CVE vulnerabilities?", default=False)
    syntax_warnings = click.confirm("Treat Python SyntaxWarnings as errors?", default=False)
    show_stats = click.confirm("Show scan performance statistics at the end?", default=False)

    output_file = None
    if report_format != "console":
        output_file = Path(
            click.prompt("Output file path", type=str)
        )

    click.echo("\n[*] Wizard completed. Starting scan...\n")

    return {
        "scan_path":       scan_path,
        "repo_url":        repo_url,
        "ai_scan":         ai_scan,
        "severity_level":  severity_level,
        "report_format":   report_format,
        "output_file":     output_file,
        "supply_chain_scan": supply_chain,
        "syntax_warnings": syntax_warnings,
        "show_stats":      show_stats,
    }


@click.command(
    help="Scan a directory, file, or remote Git repository for vulnerabilities."
)
@click.argument(
    'path',
    type=click.Path(
        exists=True, file_okay=True, dir_okay=True,
        readable=True, path_type=Path
    ),
    required=False,
)
@click.option('-u', '--url', 'repo_url', type=str,
              help="URL of a public GitHub/GitLab repository to clone and scan.")
@click.option('-c', '--config', 'config_path',
              type=click.Path(exists=True, path_type=Path),
              help="Path to a pyspector.toml config file.")
@click.option('-o', '--output', 'output_file',
              type=click.Path(path_type=Path),
              help="Path to write the report to.")
@click.option('-f', '--format', 'report_format',
              type=click.Choice(['console', 'json', 'sarif', 'html']),
              default='console',
              help="Format of the report.")
@click.option('-s', '--severity', 'severity_level',
              type=click.Choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
              default='LOW',
              help="Minimum severity level to report.")
@click.option('--ai', 'ai_scan', is_flag=True, default=False,
              help="Enable specialized scanning for AI/LLM vulnerabilities.")
@click.option('--plugin', 'plugins', multiple=True,
              help="Load and execute a plugin (can be specified multiple times)")
@click.option('--plugin-config', 'plugin_config_file',
              type=click.Path(exists=True, path_type=Path),
              help="Path to plugin configuration JSON file")
@click.option('--list-plugins', 'list_plugins', is_flag=True,
              help="List available plugins and exit")
@click.option('--supply-chain', is_flag=True, default=False,
              help="Scan dependencies for known CVE vulnerabilities.")
@click.option('--syntax-warnings', is_flag=True, default=False,
              help="Treat SyntaxWarning as errors during parsing.")
@click.option('--wizard', is_flag=True,
              help="Interactive guided scan for first-time users")
@click.option('--stats', 'show_stats', is_flag=True, default=False,
              help=(
                  "Print a detailed performance and findings statistics table "
                  "at the end of the scan (LoC/sec, memory, engine breakdown, "
                  "top rules, top files, vulnerability density, and more)."
              ))
def run_scan_command(
    path:             Optional[Path],
    repo_url:         Optional[str],
    config_path:      Optional[Path],
    output_file:      Optional[Path],
    report_format:    str,
    severity_level:   str,
    ai_scan:          bool,
    plugins:          tuple,
    plugin_config_file: Optional[Path],
    list_plugins:     bool,
    supply_chain:     bool,
    syntax_warnings:  bool,
    wizard:           bool,
    show_stats:       bool,
):
    """The main scan command with plugin and stats support."""

    # --- Wizard Mode ---
    if wizard:
        params = run_wizard()

        if params["repo_url"]:
            try:
                _parsed   = urlparse(params["repo_url"])
                _hostname = _parsed.hostname or ""
            except Exception:
                _hostname = ""

            if _hostname not in ("github.com", "gitlab.com"):
                raise click.BadParameter(
                    "URL must be a public GitHub or GitLab repository."
                )
            with tempfile.TemporaryDirectory() as temp_dir:
                click.echo(f"[*] Cloning '{params['repo_url']}' into temporary directory...")
                subprocess.run(
                    ['git', 'clone', '--depth', '1', params["repo_url"], temp_dir],
                    check=True, capture_output=True, text=True,
                )
                _execute_scan(
                    Path(temp_dir),
                    config_path,
                    params["output_file"],
                    params["report_format"],
                    params["severity_level"],
                    params["ai_scan"],
                    plugins=(),
                    plugin_config={},
                    supply_chain_scan=params["supply_chain_scan"],
                    syntax_warnings=params["syntax_warnings"],
                    show_stats=params["show_stats"],
                )
        else:
            _execute_scan(
                params["scan_path"],
                config_path,
                params["output_file"],
                params["report_format"],
                params["severity_level"],
                params["ai_scan"],
                plugins=(),
                plugin_config={},
                supply_chain_scan=params["supply_chain_scan"],
                syntax_warnings=params["syntax_warnings"],
                show_stats=params["show_stats"],
            )
        return

    # Handle --list-plugins
    if list_plugins:
        plugin_manager = get_plugin_manager()
        available  = plugin_manager.list_available_plugins()
        registered = plugin_manager.registry.list_plugins()

        click.echo("\n=== Available Plugins ===")
        if not available:
            click.echo("No plugins found")
            click.echo(f"Plugin directory: {plugin_manager.plugin_dir}")
        else:
            for plugin_name in available:
                info = next((p for p in registered if p["name"] == plugin_name), None)
                if info:
                    status = "trusted" if info.get("trusted") else "untrusted"
                    click.echo(
                        f"  - {plugin_name} ({status}) "
                        f"- v{info.get('version', 'unknown')}"
                    )
                else:
                    click.echo(f"  - {plugin_name} (not registered)")
        click.echo()
        return

    if not path and not repo_url:
        raise click.UsageError("You must provide either a PATH or a --url to scan.")
    if path and repo_url:
        raise click.UsageError("You cannot provide both a PATH and a --url.")

    # Load plugin config if provided
    plugin_config: Dict[str, Any] = {}
    if plugin_config_file:
        try:
            with open(plugin_config_file, 'r') as f:
                plugin_config = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            click.echo(
                click.style(f"Warning: Could not load plugin config: {e}", fg="yellow")
            )

    if repo_url:
        try:
            _parsed   = urlparse(repo_url)
            _hostname = _parsed.hostname or ""
        except Exception:
            _hostname = ""

        if _hostname not in ("github.com", "gitlab.com"):
            raise click.BadParameter(
                "URL must be a public GitHub or GitLab repository."
            )

        with tempfile.TemporaryDirectory() as temp_dir:
            click.echo(f"[*] Cloning '{repo_url}' into temporary directory...")
            try:
                subprocess.run(
                    ['git', 'clone', '--depth', '1', repo_url, temp_dir],
                    check=True, capture_output=True, text=True,
                )
                _execute_scan(
                    Path(temp_dir), config_path, output_file,
                    report_format, severity_level, ai_scan,
                    plugins, plugin_config, supply_chain,
                    syntax_warnings, show_stats,
                )
            except subprocess.CalledProcessError as e:
                click.echo(
                    click.style(
                        f"Error: Failed to clone repository.\n{e.stderr}", fg="red"
                    )
                )
                sys.exit(1)
            except FileNotFoundError:
                click.echo(
                    click.style(
                        "Error: 'git' command not found. "
                        "Please ensure Git is installed and in your PATH.",
                        fg="red",
                    )
                )
                sys.exit(1)
    else:
        _execute_scan(
            path, config_path, output_file,
            report_format, severity_level, ai_scan,
            plugins, plugin_config, supply_chain,
            syntax_warnings, show_stats,
        )


def _execute_scan(
    scan_path:        Path,
    config_path:      Optional[Path],
    output_file:      Optional[Path],
    report_format:    str,
    severity_level:   str,
    ai_scan:          bool,
    plugins:          tuple,
    plugin_config:    dict,
    supply_chain_scan: bool   = False,
    syntax_warnings:   bool   = False,
    show_stats:        bool   = False,
):
    """
    Core scan orchestrator.

    When *show_stats* is True a StatsCollector is attached to the run.
    It samples resource usage in a background thread, records per-phase
    metrics, and prints the ASCII stats table after the normal report.
    """

    # ── Stats initialisation ──────────────────────────────────────────────
    stats: Optional[StatsCollector] = None
    if show_stats:
        stats = StatsCollector()
        stats.start()

    start_time = time.time()

    config          = load_config(config_path)
    rules_toml_str  = get_default_rules(ai_scan)

    # Let the stats collector parse the rule TOML to build its detection map
    if stats:
        stats.record_rules(rules_toml_str)

    click.echo(f"[*] Starting PySpector scan on '{scan_path}'...")

    # ── Load Baseline ─────────────────────────────────────────────────────
    baseline_path = (
        scan_path / ".pyspector_baseline.json"
        if scan_path.is_dir()
        else scan_path.parent / ".pyspector_baseline.json"
    )
    ignored_fingerprints: set = set()
    if baseline_path.exists():
        try:
            with baseline_path.open('r') as f:
                baseline_data = json.load(f)
                ignored_fingerprints = set(
                    baseline_data.get("ignored_fingerprints", [])
                )
                click.echo(
                    f"[*] Loaded baseline from '{baseline_path}', "
                    f"ignoring {len(ignored_fingerprints)} known issues."
                )
        except json.JSONDecodeError:
            click.echo(
                click.style(
                    f"Warning: Could not parse baseline file '{baseline_path}'.",
                    fg="yellow",
                )
            )

    # ── AST Generation ────────────────────────────────────────────────────
    t_parse = time.time()
    ast_stats_meta: Dict[str, int] = {}
    python_files_data = get_python_file_asts(
        scan_path,
        enable_syntax_warnings=syntax_warnings,
        _stats_meta=ast_stats_meta,
    )
    click.echo(f"[*] Successfully parsed {len(python_files_data)} Python files in {time.time()-t_parse:.2f}s")

    if stats:
        stats.record_files(
            python_files_data,
            skipped=ast_stats_meta.get('skipped', 0),
            errors=ast_stats_meta.get('errors',  0),
        )

    # ── Supply Chain Scanning ─────────────────────────────────────────────
    if supply_chain_scan:
        try:
            from pyspector._rust_core import scan_supply_chain
            click.echo("\n[*] Scanning dependencies for known vulnerabilities...")
            dep_vulns = scan_supply_chain(str(scan_path.resolve()))

            if dep_vulns:
                click.echo(f"\n{'='*60}")
                click.echo(f"  SUPPLY CHAIN VULNERABILITIES ({len(dep_vulns)} found)")
                click.echo(f"{'='*60}")

                for vuln in dep_vulns:
                    sev_color = {
                        'CRITICAL': 'bright_red',
                        'HIGH':     'red',
                        'MEDIUM':   'yellow',
                        'LOW':      'blue',
                        'UNKNOWN':  'white',
                    }.get(vuln['severity'], 'white')

                    click.echo(
                        f"\n[{click.style(vuln['severity'], fg=sev_color)}] "
                        f"{vuln['dependency']} @ {vuln['version']}"
                    )
                    click.echo(f"    Vulnerability: {vuln['vulnerability_id']}")
                    click.echo(f"    File: {vuln['file']}")
                    click.echo(f"    Summary: {vuln['summary'][:100]}...")
                    if vuln.get('fixed_version'):
                        click.echo(f"    Fixed in: {vuln['fixed_version']}")
                click.echo()
            else:
                click.echo("[+] No known vulnerabilities found in dependencies")
        except ImportError:
            click.echo(
                click.style(
                    "Error: Supply chain scanner not available. Reinstall PySpector.",
                    fg="red",
                )
            )
        except Exception as e:
            click.echo(click.style(f"Error during supply chain scan: {e}", fg="red"))

    # ── Run Scan (Rust core) ───────────────────────────────────────────────
    t_rust = time.time()
    try:
        raw_issues = run_scan(
            str(scan_path.resolve()), rules_toml_str, config, python_files_data
        )
        click.echo(f"[*] Rust core scan: {time.time()-t_rust:.2f}s")
    except ValueError as e:
        click.echo(
            click.style(
                f"Configuration error: {e}\n"
                "Invalid configuration detected. "
                "Please verify your settings and retry.",
                fg="red",
            )
        )
        if stats:
            stats.stop()
        return
    except RuntimeError as e:
        click.echo(
            click.style(
                f"Runtime error during execution: {e}\n"
                "The scan engine encountered an operational error. "
                "Please retry or open an Issue if the problem persists.",
                fg="red",
            )
        )
        if stats:
            stats.stop()
        return
    except Exception as e:
        click.echo(
            click.style(
                f"A critical Exception was raised during the scan process: {e}",
                fg="red",
            )
        )
        if stats:
            stats.stop()
        return

    # Record raw issues before any filtering
    if stats:
        stats.record_raw_issues(raw_issues)

    # ── Filter by Severity and Baseline ───────────────────────────────────
    severity_map = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
    min_severity_val = severity_map[severity_level.upper()]

    # Separate the two filter passes so we can count each independently
    severity_passed = [
        issue for issue in raw_issues
        if severity_map[str(issue.severity).split('.')[-1].upper()] >= min_severity_val
    ]
    final_issues = [
        issue for issue in severity_passed
        if issue.get_fingerprint() not in ignored_fingerprints
    ]

    _severity_filtered = len(raw_issues) - len(severity_passed)
    _baseline_ignored  = len(severity_passed) - len(final_issues)

    if stats:
        stats.record_final_issues(
            final_issues,
            severity_filtered=_severity_filtered,
            baseline_ignored=_baseline_ignored,
        )

    # ── Plugins ────────────────────────────────────────────────────────────
    findings_dict = [
        {
            "rule_id":     issue.rule_id,
            "description": issue.description,
            "file":        issue.file_path,
            "line":        issue.line_number,
            "code":        issue.code,
            "severity":    str(issue.severity).split('.')[-1],
            "remediation": issue.remediation,
        }
        for issue in final_issues
    ]

    if plugins:
        try:
            execute_plugins(findings_dict, scan_path, list(plugins), plugin_config)
        except click.ClickException as exc:
            click.echo(click.style(f"[!] Plugin error: {exc}", fg="red"))

    # ── Generate Report ────────────────────────────────────────────────────
    reporter = Reporter(final_issues, report_format)
    output   = reporter.generate()

    if output_file:
        try:
            output_file.write_text(output, encoding='utf-8')
            click.echo(f"\n[+] Report saved to '{output_file}'")
        except IOError as e:
            click.echo(click.style(f"Error writing to output file: {e}", fg="red"))
    else:
        click.echo(output)

    end_time = time.time()
    click.echo(
        f"\n[*] Scan finished in {end_time - start_time:.2f} seconds. "
        f"Found {len(final_issues)} issues."
    )
    if len(raw_issues) > len(final_issues):
        click.echo(
            f"[*] Ignored {len(raw_issues) - len(final_issues)} issues "
            f"based on severity level or baseline."
        )

    # ── Stats Table ────────────────────────────────────────────────────────
    if stats:
        stats.stop()
        click.echo("\n")
        click.echo(stats.render_table())

    sys.stdout.flush()
    sys.stderr.flush()


@click.command(
    help="Start the interactive TUI to review and baseline findings."
)
@click.argument(
    'report_file',
    type=click.Path(exists=True, readable=True, path_type=Path),
)
def triage_command(report_file: Path):
    """The TUI command for baselining."""
    if not report_file.name.endswith('.json'):
        click.echo(
            click.style(
                "Error: Triage mode only supports JSON report files "
                "generated by PySpector.",
                fg="red",
            )
        )
        return

    try:
        with report_file.open('r', encoding='utf-8') as f:
            issues_data = json.load(f)

        baseline_path = report_file.parent / ".pyspector_baseline.json"
        run_triage_tui(issues_data.get("issues", []), baseline_path)

    except (json.JSONDecodeError, IOError) as e:
        click.echo(click.style(f"Error reading report file: {e}", fg="red"))


# --- Plugin Management Commands ---

@click.group(help="Manage PySpector plugins")
def plugin():
    """Plugin management commands"""
    pass


@plugin.command(name="list", help="List all available plugins")
def list_plugins_command():
    """List available plugins"""
    plugin_manager = get_plugin_manager()
    available  = plugin_manager.list_available_plugins()
    registered = plugin_manager.registry.list_plugins()

    click.echo("\n" + "="*60)
    click.echo("PySpector Plugins")
    click.echo("="*60)

    if not available:
        click.echo("\nNo plugins found in plugin directory")
        click.echo(f"Plugin directory: {plugin_manager.plugin_dir}")
    else:
        click.echo(f"\nFound {len(available)} plugin(s):\n")

        for plugin_name in available:
            info = next((p for p in registered if p["name"] == plugin_name), None)

            if info:
                is_trusted   = bool(info.get("trusted"))
                status_text  = "trusted" if is_trusted else "untrusted"
                status_color = "green"   if is_trusted else "yellow"
                status       = click.style(status_text, fg=status_color)
                click.echo(f"  {plugin_name}")
                click.echo(f"    Status: {status}")
                click.echo(f"    Version: {info.get('version', 'unknown')}")
                click.echo(f"    Author: {info.get('author', 'unknown')}")
                click.echo(f"    Category: {info.get('category', 'general')}")
            else:
                click.echo(f"  {plugin_name}")
                click.echo(
                    f"    Status: {click.style('not registered', fg='red')}"
                )

            click.echo()

    click.echo(f"Plugin directory: {plugin_manager.plugin_dir}")
    click.echo("="*60 + "\n")


@plugin.command(help="Trust a plugin")
@click.argument('plugin_name')
def trust(plugin_name: str):
    """Trust a plugin"""
    plugin_manager = get_plugin_manager()
    plugin_name, renamed = _normalize_plugin_name_cli(plugin_name)
    if renamed:
        click.echo(f"[*] Normalised plugin name to '{plugin_name}'")
    plugin_manager.trust_plugin(plugin_name)


@plugin.command(help="Show plugin information")
@click.argument('plugin_name')
def info(plugin_name: str):
    """Show detailed plugin information"""
    plugin_manager = get_plugin_manager()
    plugin_name, renamed = _normalize_plugin_name_cli(plugin_name)
    if renamed:
        click.echo(f"[*] Normalised plugin name to '{plugin_name}'")

    plugin_path = plugin_manager.plugin_dir / f"{plugin_name}.py"

    if not plugin_path.exists():
        click.echo(click.style(f"Plugin '{plugin_name}' not found", fg="red"))
        return

    info_data = plugin_manager.registry.get_plugin_info(plugin_name)

    click.echo(f"\n{'='*60}")
    click.echo(f"Plugin: {plugin_name}")
    click.echo('='*60)

    if info_data:
        trusted = (
            click.style("Yes", fg="green")
            if info_data.get('trusted')
            else click.style("No", fg="red")
        )
        click.echo(f"Trusted: {trusted}")
        click.echo(f"Version: {info_data.get('version', 'unknown')}")
        click.echo(f"Author: {info_data.get('author', 'unknown')}")
        click.echo(f"Category: {info_data.get('category', 'general')}")
        click.echo(f"Path: {info_data.get('path', 'unknown')}")

        current_checksum = PluginSecurity.calculate_checksum(plugin_path)
        stored_checksum  = info_data.get('checksum', '')

        if current_checksum == stored_checksum:
            click.echo(f"Checksum: {click.style('valid', fg='green')}")
        else:
            click.echo(f"Checksum: {click.style('modified', fg='red')}")
    else:
        click.echo(click.style("Not registered", fg="yellow"))
        click.echo(f"Path: {plugin_path}")

    click.echo(f"\n{'='*60}\n")


@plugin.command(help="Install a plugin from a file")
@click.argument('plugin_file', type=click.Path(exists=True, path_type=Path))
@click.option('--name', help="Custom name for the plugin")
@click.option('--trust', is_flag=True, help="Automatically trust the plugin")
def install(plugin_file: Path, name: str, trust: bool):
    """Install a plugin from a file"""
    plugin_manager = get_plugin_manager()

    plugin_name, renamed = _normalize_plugin_name_cli(name or plugin_file.stem)
    if renamed:
        click.echo(f"[*] Normalised plugin name to '{plugin_name}'")

    target_path     = plugin_manager.plugin_dir / f"{plugin_name}.py"
    overwrite_allowed = False

    if target_path.exists():
        if not click.confirm(f"Plugin '{plugin_name}' already exists. Overwrite?"):
            return
        overwrite_allowed = True

    is_safe, warning = PluginSecurity.validate_plugin_code(plugin_file)
    if not is_safe:
        click.echo(click.style(f"Security warning: {warning}", fg="red"))
        if not trust and not click.confirm("Install anyway?"):
            return

    if trust:
        if not plugin_manager.trust_plugin(
            plugin_name, plugin_file, overwrite=overwrite_allowed
        ):
            return
        click.echo(click.style(f"[+] Plugin stored at {target_path}", fg="green"))
    else:
        staged_path = plugin_manager.install_plugin_file(
            plugin_name, plugin_file, overwrite=overwrite_allowed,
        )
        if not staged_path:
            return
        click.echo(click.style(f"[+] Plugin installed to {staged_path}", fg="green"))
        click.echo(f"[*] Run 'pyspector plugin trust {plugin_name}' to trust it")


@plugin.command(help="Remove a plugin")
@click.argument('plugin_name')
@click.option('--force', is_flag=True, help="Force removal without confirmation")
def remove(plugin_name: str, force: bool):
    """Remove a plugin"""
    plugin_manager = get_plugin_manager()
    plugin_name, renamed = _normalize_plugin_name_cli(plugin_name)
    if renamed:
        click.echo(f"[*] Normalised plugin name to '{plugin_name}'")

    plugin_path = plugin_manager.plugin_dir / f"{plugin_name}.py"

    if not plugin_path.exists():
        click.echo(click.style(f"Plugin '{plugin_name}' not found", fg="red"))
        return

    if not force:
        if not click.confirm(f"Remove plugin '{plugin_name}'?"):
            return

    try:
        plugin_path.unlink()
        if plugin_name in plugin_manager.registry.plugins:
            del plugin_manager.registry.plugins[plugin_name]
            plugin_manager.registry.save_registry()
        click.echo(click.style(f"[+] Plugin '{plugin_name}' removed", fg="green"))
    except Exception as e:
        click.echo(click.style(f"Error removing plugin: {e}", fg="red"))


# Add commands to the CLI group
cli.add_command(run_scan_command, name="scan")
cli.add_command(triage_command,   name="triage")
cli.add_command(plugin)