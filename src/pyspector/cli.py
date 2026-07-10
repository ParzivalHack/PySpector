from __future__ import annotations
import click
import time
import json
import ast
import contextlib
import os
import subprocess
import tempfile
import sys
import threading
import warnings
from importlib.metadata import version as _pkg_version, PackageNotFoundError
from pathlib import Path
from typing import Optional, Dict, Any, List, cast

from .ast_cache import IncrementalAstCache, get_cache
from ._ast_encode import AstEncoder
from .config import load_config, get_default_rules
from .reporting import Reporter
from .triage import run_triage_tui
from .stats import StatsCollector
from .git_history import iter_all_blobs, iter_staged_files
import requests
from urllib.parse import urlparse

# Import the Rust core from its new location
try:
    from pyspector._rust_core import run_scan, scan_blobs
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

def _dbg(debug: bool, msg: str = "", **style_kwargs) -> None:
    """Emit *msg* via click.echo only when --debug is enabled.

    Used to gate progress/info chatter so the default output stays focused on
    findings, warnings and errors. Errors and findings should call click.echo
    directly, not this helper.
    """
    if not debug:
        return
    if style_kwargs:
        click.echo(click.style(msg, **style_kwargs))
    else:
        click.echo(msg)


_BANNER = r"""
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


_SEV_COLOR: Dict[str, str] = {
    "CRITICAL": "bright_red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "blue",
}


@contextlib.contextmanager
def _silence_fd1(active: bool):
    """Redirect file descriptor 1 (stdout) to /dev/null when *active* is True.

    Used to swallow ``println!`` output emitted by the Rust core during a scan
    when --debug is not set. Python-side ``click.echo`` calls inside the block
    are also suppressed; do not place user-facing output (findings, errors)
    inside this context.
    """
    if not active:
        yield
        return
    sys.stdout.flush()
    saved_fd = os.dup(1)
    devnull_fd = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(devnull_fd, 1)
        yield
    finally:
        sys.stdout.flush()
        os.dup2(saved_fd, 1)
        os.close(saved_fd)
        os.close(devnull_fd)


def _get_version() -> str:
    try:
        return _pkg_version("pyspector")
    except PackageNotFoundError:
        return "unknown"


def _print_banner() -> None:
    """Print the name banner, version, credits and the startup joke.

    Shown at the start of every scan. The verbose ``[*]`` progress lines that
    follow are gated by --debug.
    """
    click.echo(click.style(_BANNER))
    click.echo(f"Version: {_get_version()}")
    click.echo("Made with <3 by github.com/ParzivalHack\n")
    note = get_startup_note()
    click.echo(click.style(f"{note}\n", fg="bright_black", italic=True))


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


def _is_path_excluded(file_path: Path, root: Path, patterns: List[str]) -> bool:
    """Return True if *file_path* matches any of the *patterns* (fnmatch-style).

    Patterns are matched against the path relative to *root*, against the
    absolute path, and against each individual path component. This lets
    bare names like ".venv" or "node_modules" prune whole subtrees regardless
    of depth.
    """
    import fnmatch
    try:
        rel = file_path.relative_to(root)
    except ValueError:
        rel = file_path
    rel_str = str(rel).replace("\\", "/")
    abs_str = str(file_path).replace("\\", "/")
    parts = set(rel.parts) | set(file_path.parts)
    for pat in patterns:
        if fnmatch.fnmatch(rel_str, pat) or fnmatch.fnmatch(abs_str, pat):
            return True
        if pat in parts:
            return True
    return False


def get_python_file_asts(
    path: Path,
    enable_syntax_warnings: bool = False,
    _stats_meta: Optional[Dict[str, int]] = None,
    debug: bool = False,
    exclude: Optional[List[str]] = None,
    cache: Optional[IncrementalAstCache] = None,
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
        cache: Optional incremental AST cache. When supplied (and syntax
            warnings are not being promoted to errors), the cached AST JSON
            is reused instead of re-running ast.parse + json.dumps. The cache
            suppresses SyntaxWarning internally, so it is bypassed whenever
            ``enable_syntax_warnings`` is True to preserve that diagnostic.
    """
    if _stats_meta is not None:
        _stats_meta['skipped'] = 0
        _stats_meta['errors']  = 0

    results = []
    exclude_patterns = list(exclude or [])
    root = path if path.is_dir() else path.parent
    if path.is_dir():
        files_to_scan = [
            p for p in path.glob("**/*.py")
            if not _is_path_excluded(p, root, exclude_patterns)
        ]
    else:
        files_to_scan = [path]

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
                    _dbg(
                        debug,
                        f"Info: Skipped {display_path} (test file or fixture)",
                        fg="blue",
                    )
                    if _stats_meta is not None:
                        _stats_meta['skipped'] += 1
                    continue

                try:
                    content = py_file.read_text(encoding="utf-8")
                    if cache is not None and not enable_syntax_warnings:
                        ast_json = cache.get_ast_json(py_file, content)
                    else:
                        parsed_ast = ast.parse(content, filename=str(py_file))
                        ast_json = json.dumps(parsed_ast, cls=AstEncoder)
                    results.append(
                        {
                            "file_path": str(py_file.resolve()),
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


def _scan_to_issues(
    scan_path:      Path,
    config_path:    Optional[Path],
    severity_level: str,
    ai_scan:        bool,
    syntax_warnings: bool = False,
    debug:          bool  = False,
    cache:          Optional[IncrementalAstCache] = None,
) -> List:
    """Run a scan and return the filtered issue list. Used by watch mode."""
    config         = load_config(config_path)
    rules_toml_str = get_default_rules(ai_scan)

    if cache is None:
        cache = get_cache(scan_path)

    baseline_path = (
        scan_path / ".pyspector_baseline.json"
        if scan_path.is_dir()
        else scan_path.parent / ".pyspector_baseline.json"
    )
    ignored_fingerprints: set = set()
    if baseline_path.exists():
        try:
            with baseline_path.open("r") as f:
                ignored_fingerprints = set(
                    json.load(f).get("ignored_fingerprints", [])
                )
        except json.JSONDecodeError:
            pass

    python_files_data = get_python_file_asts(
        scan_path,
        enable_syntax_warnings=syntax_warnings,
        debug=debug,
        exclude=list(config.get("exclude", [])),
        cache=cache,
    )

    with _silence_fd1(not debug):
        raw_issues = run_scan(
            str(scan_path.resolve()), rules_toml_str, config, python_files_data
        )

    severity_map = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    min_sev = severity_map[severity_level.upper()]

    return [
        issue for issue in raw_issues
        if severity_map[str(issue.severity).split(".")[-1].upper()] >= min_sev
        and issue.get_fingerprint() not in ignored_fingerprints
    ]


def _fmt_watch_issue(issue, tag: str, tag_color: str) -> str:
    """Format one issue as a compact single-line string for watch-mode diffs."""
    sev = str(issue.severity).split(".")[-1].upper()
    return (
        click.style(f"  {tag:<10}", fg=tag_color, bold=True)
        + "  "
        + click.style(f"[{sev}]", fg=_SEV_COLOR.get(sev, "white"))
        + f"  {issue.rule_id}"
        + f"  {issue.file_path}:{issue.line_number}"
        + f"  `{issue.code.strip()[:60]}`"
    )


# --- Main CLI Logic ---

@click.group()
@click.option('--ai', 'ai_scan', is_flag=True, default=False,
              help="Enable the specialized ruleset for AI/LLM vulnerability scanning.")
@click.option('-s', '--severity', 'severity_level',
              type=click.Choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
              default='LOW', show_default=True,
              help="Minimum severity level to report.")
@click.option('-f', '--format', 'report_format',
              type=click.Choice(['console', 'json', 'sarif', 'html']),
              default='console', show_default=True,
              help="Output format: console, json, sarif, or html.")
@click.option('-c', '--config', 'config_path',
              type=click.Path(path_type=Path),
              help="Path to a pyspector.toml configuration file.")
@click.option('-o', '--output', 'output_file',
              type=click.Path(path_type=Path),
              help="Path to write the report to (default: stdout).")
@click.option('-u', '--url', 'repo_url', type=str,
              help="URL of a public GitHub or GitLab repository to clone and scan.")
@click.option('--supply-chain', is_flag=True, default=False,
              help="Check project dependencies against the OSV database for known CVEs.")
@click.option('--stats', 'show_stats', is_flag=True, default=False,
              help="Print a performance and findings statistics table after the scan.")
@click.option('--debug', is_flag=True, default=False,
              help="Show all informational/progress messages.")
@click.option('--wizard', is_flag=True, default=False,
              help="Launch interactive guided scan mode — ideal for first-time users.")
@click.pass_context
def cli(
    ctx: click.Context,
    ai_scan: bool,
    severity_level: str,
    report_format: str,
    config_path: Optional[Path],
    output_file: Optional[Path],
    repo_url: Optional[str],
    supply_chain: bool,
    show_stats: bool,
    debug: bool,
    wizard: bool,
):
    """
    PySpector: A high-performance, security-focused static analysis tool
    for Python, powered by Rust.
    """
    ctx.ensure_object(dict)
    ctx.default_map = {
        'scan': {
            'ai_scan':        ai_scan,
            'severity_level': severity_level,
            'report_format':  report_format,
            'config_path':    config_path,
            'output_file':    output_file,
            'repo_url':       repo_url,
            'supply_chain':   supply_chain,
            'show_stats':     show_stats,
            'debug':          debug,
            'wizard':         wizard,
        },
        'watch': {
            'ai_scan':        ai_scan,
            'severity_level': severity_level,
            'config_path':    config_path,
            'debug':          debug,
        },
    }


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
    debug = click.confirm("Show verbose debug output?", default=False)

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
        "debug":           debug,
    }


@click.command(
    help=(
        "Scan a file, directory, or remote Git repository for vulnerabilities.\n\n"
        "PATH: local file or directory to scan. Omit PATH and use --url to scan a remote repo."
    )
)
@click.argument(
    'path',
    type=click.Path(
        exists=True, file_okay=True, dir_okay=True,
        readable=True, path_type=Path
    ),
    required=False,
    metavar='[PATH]',
)
@click.option('-u', '--url', 'repo_url', type=str,
              help="URL of a public GitHub or GitLab repository to clone and scan.")
@click.option('-c', '--config', 'config_path',
              type=click.Path(exists=True, path_type=Path),
              help="Path to a pyspector.toml config file (overrides defaults).")
@click.option('-o', '--output', 'output_file',
              type=click.Path(path_type=Path),
              help="Path to write the report to (default: print to stdout).")
@click.option('-f', '--format', 'report_format',
              type=click.Choice(['console', 'json', 'sarif', 'html']),
              default='console',
              show_default=True,
              help="Output format: console, json, sarif, or html.")
@click.option('-s', '--severity', 'severity_level',
              type=click.Choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
              default='LOW',
              show_default=True,
              help="Minimum severity level to report.")
@click.option('--ai', 'ai_scan', is_flag=True, default=False,
              help="Enable the specialized ruleset for AI/LLM vulnerability scanning.")
@click.option('--supply-chain', is_flag=True, default=False,
              help="Check project dependencies against the OSV database for known CVEs.")
@click.option('--syntax-warnings', is_flag=True, default=False,
              help="Treat Python SyntaxWarnings as errors and exclude affected files.")
@click.option('--wizard', is_flag=True,
              help="Launch interactive guided scan mode — ideal for first-time users.")
@click.option('--stats', 'show_stats', is_flag=True, default=False,
              help=(
                  "Print a detailed performance and findings statistics table "
                  "at the end of the scan (LoC/sec, memory, engine breakdown, "
                  "top rules, top files, vulnerability density, and more)."
              ))
@click.option('--debug', is_flag=True, default=False,
              help="Show all informational/progress messages and the banner. "
                   "Without this flag only findings, warnings and errors are printed.")
def run_scan_command(
    path:             Optional[Path],
    repo_url:         Optional[str],
    config_path:      Optional[Path],
    output_file:      Optional[Path],
    report_format:    str,
    severity_level:   str,
    ai_scan:          bool,
    supply_chain:     bool,
    syntax_warnings:  bool,
    wizard:           bool,
    show_stats:       bool,
    debug:            bool,
):
    """The main scan command with stats support."""

    _print_banner()

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
                _dbg(params["debug"], f"[*] Cloning '{params['repo_url']}' into temporary directory...")
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
                    supply_chain_scan=params["supply_chain_scan"],
                    syntax_warnings=params["syntax_warnings"],
                    show_stats=params["show_stats"],
                    debug=params["debug"],
                )
        else:
            _execute_scan(
                params["scan_path"],
                config_path,
                params["output_file"],
                params["report_format"],
                params["severity_level"],
                params["ai_scan"],
                supply_chain_scan=params["supply_chain_scan"],
                syntax_warnings=params["syntax_warnings"],
                show_stats=params["show_stats"],
                debug=params["debug"],
            )
        return

    if not path and not repo_url:
        raise click.UsageError("You must provide either a PATH or a --url to scan.")
    if path and repo_url:
        raise click.UsageError("You cannot provide both a PATH and a --url.")

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
            _dbg(debug, f"[*] Cloning '{repo_url}' into temporary directory...")
            try:
                subprocess.run(
                    ['git', 'clone', '--depth', '1', repo_url, temp_dir],
                    check=True, capture_output=True, text=True,
                )
                _execute_scan(
                    Path(temp_dir), config_path, output_file,
                    report_format, severity_level, ai_scan,
                    supply_chain,
                    syntax_warnings, show_stats, debug,
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
            supply_chain,
            syntax_warnings, show_stats, debug,
        )


def _execute_scan(
    scan_path:        Path,
    config_path:      Optional[Path],
    output_file:      Optional[Path],
    report_format:    str,
    severity_level:   str,
    ai_scan:          bool,
    supply_chain_scan: bool   = False,
    syntax_warnings:   bool   = False,
    show_stats:        bool   = False,
    debug:             bool   = False,
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

    _dbg(debug, f"[*] Starting PySpector scan on '{scan_path}'...")

    # ── AST Cache ─────────────────────────────────────────────────────────
    cache = get_cache(scan_path)

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
                _dbg(
                    debug,
                    f"[*] Loaded baseline from '{baseline_path}', "
                    f"ignoring {len(ignored_fingerprints)} known issues.",
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
        debug=debug,
        exclude=list(config.get("exclude", [])),
        cache=cache,
    )
    _dbg(debug, f"[*] Successfully parsed {len(python_files_data)} Python files in {time.time()-t_parse:.2f}s")

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
            _dbg(debug, "\n[*] Scanning dependencies for known vulnerabilities...")
            with _silence_fd1(not debug):
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
                _dbg(debug, "[+] No known vulnerabilities found in dependencies")
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
        with _silence_fd1(not debug):
            raw_issues = run_scan(
                str(scan_path.resolve()), rules_toml_str, config, python_files_data
            )
        _dbg(debug, f"[*] Rust core scan: {time.time()-t_rust:.2f}s")
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

    # ── Generate Report ────────────────────────────────────────────────────
    reporter = Reporter(final_issues, report_format)
    output   = reporter.generate()

    if output_file:
        try:
            output_file.write_text(output, encoding='utf-8')
            _dbg(debug, f"\n[+] Report saved to '{output_file}'")
        except IOError as e:
            click.echo(click.style(f"Error writing to output file: {e}", fg="red"))
    else:
        click.echo(output)

    end_time = time.time()
    _dbg(
        debug,
        f"\n[*] Scan finished in {end_time - start_time:.2f} seconds. "
        f"Found {len(final_issues)} issues.",
    )
    if len(raw_issues) > len(final_issues):
        _dbg(
            debug,
            f"[*] Ignored {len(raw_issues) - len(final_issues)} issues "
            f"based on severity level or baseline.",
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


# --- Secret Detection Commands ---

def _load_ignored_fingerprints(baseline_path: Path) -> set:
    """Loads the set of ignored fingerprints from a .pyspector_baseline.json file."""
    if not baseline_path.exists():
        return set()
    try:
        with baseline_path.open('r') as f:
            data = json.load(f)
            return set(data.get("ignored_fingerprints", []))
    except (json.JSONDecodeError, IOError):
        return set()


def _run_secrets_scan(
    scan_path: Path,
    config_path: Optional[Path],
    history: bool,
    staged_only: bool,
    entropy_threshold: Optional[float],
) -> list:
    """
    Runs the secret-detection ruleset over the working tree and/or git
    history/staged content. Returns a fingerprint-deduplicated list of Issue
    objects (before baseline/severity filtering).
    """
    config = load_config(config_path)
    if entropy_threshold is not None:
        config['entropy_threshold'] = entropy_threshold

    rules_toml_str = get_default_rules(secrets_scan=True)

    all_issues = []

    if staged_only:
        blobs = [
            {"path": path, "content": content, "commit": "staged"}
            for path, content in iter_staged_files(scan_path)
        ]
        if blobs:
            all_issues.extend(scan_blobs(blobs, rules_toml_str, config))
    else:
        # Working tree: no Python ASTs are needed (secrets are regex/entropy only),
        # which keeps this scan fast even on large repos.
        all_issues.extend(run_scan(str(scan_path.resolve()), rules_toml_str, config, []))

        if history:
            click.echo("[*] Scanning full git history for secrets (this may take a while on large repos)...")
            blobs = [
                {"path": path, "content": content, "commit": "history"}
                for path, content in iter_all_blobs(scan_path)
            ]
            if blobs:
                all_issues.extend(scan_blobs(blobs, rules_toml_str, config))

    seen = set()
    deduped = []
    for issue in all_issues:
        fingerprint = issue.get_fingerprint()
        if fingerprint not in seen:
            seen.add(fingerprint)
            deduped.append(issue)

    return deduped


@click.group(help="Detect hardcoded secrets in the working tree, staged changes, or full git history.")
def secrets():
    """Secret detection commands."""
    pass


@secrets.command(name="scan", help="Scan for hardcoded secrets.")
@click.argument('path', type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path), required=False, default=Path('.'))
@click.option('-c', '--config', 'config_path', type=click.Path(exists=True, path_type=Path), help="Path to a pyspector config TOML file.")
@click.option('-o', '--output', 'output_file', type=click.Path(path_type=Path), help="Path to write the report to.")
@click.option('-f', '--format', 'report_format', type=click.Choice(['console', 'json', 'sarif', 'html']), default='console', help="Format of the report.")
@click.option('-s', '--severity', 'severity_level', type=click.Choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']), default='LOW', help="Minimum severity level to report.")
@click.option('--history', is_flag=True, default=False, help="Also scan the full git history (all commits), not just the working tree.")
@click.option('--staged-only', is_flag=True, default=False, help="Scan only staged (git diff --cached) content. Intended for pre-commit hooks.")
@click.option('--entropy-threshold', type=float, default=None, help="Override the Shannon-entropy threshold (bits/char) for the high-entropy rule.")
@click.option('--fail-on-findings/--no-fail-on-findings', 'fail_on_findings', default=True, help="Exit non-zero if unbaselined findings remain (default: enabled, for CI use).")
def secrets_scan_command(
    path: Path,
    config_path: Optional[Path],
    output_file: Optional[Path],
    report_format: str,
    severity_level: str,
    history: bool,
    staged_only: bool,
    entropy_threshold: Optional[float],
    fail_on_findings: bool,
):
    """Scan for hardcoded secrets and exit non-zero if any unbaselined findings remain."""
    if staged_only and history:
        raise click.UsageError("--staged-only and --history cannot be used together.")

    start_time = time.time()
    click.echo(f"[*] Starting PySpector secret scan on '{path}'...")

    issues = _run_secrets_scan(path, config_path, history, staged_only, entropy_threshold)

    baseline_path = path / ".pyspector_baseline.json"
    ignored_fingerprints = _load_ignored_fingerprints(baseline_path)
    if ignored_fingerprints:
        click.echo(f"[*] Loaded baseline from '{baseline_path}', ignoring {len(ignored_fingerprints)} known finding(s).")

    severity_map = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
    min_severity_val = severity_map[severity_level.upper()]

    final_issues = [
        issue for issue in issues
        if (severity_map[str(issue.severity).split('.')[-1].upper()] >= min_severity_val
            and issue.get_fingerprint() not in ignored_fingerprints)
    ]

    reporter = Reporter(final_issues, report_format)
    output = reporter.generate()

    if output_file:
        try:
            output_file.write_text(output, encoding='utf-8')
            click.echo(f"\n[+] Report saved to '{output_file}'")
        except IOError as e:
            click.echo(click.style(f"Error writing to output file: {e}", fg="red"))
    else:
        click.echo(output)

    end_time = time.time()
    click.echo(f"\n[*] Secret scan finished in {end_time - start_time:.2f} seconds. Found {len(final_issues)} unbaselined issue(s).")
    if len(issues) > len(final_issues):
        click.echo(f"[*] Ignored {len(issues) - len(final_issues)} finding(s) based on severity level or baseline.")

    sys.stdout.flush()
    sys.stderr.flush()

    if fail_on_findings and final_issues:
        sys.exit(1)


@secrets.command(name="baseline", help="Snapshot current secret findings into .pyspector_baseline.json for incremental adoption on legacy repos.")
@click.argument('path', type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path), required=False, default=Path('.'))
@click.option('-c', '--config', 'config_path', type=click.Path(exists=True, path_type=Path), help="Path to a pyspector config TOML file.")
@click.option('--history', is_flag=True, default=False, help="Also include findings from the full git history in the baseline.")
@click.option('--entropy-threshold', type=float, default=None, help="Override the Shannon-entropy threshold (bits/char) for the high-entropy rule.")
def secrets_baseline_command(path: Path, config_path: Optional[Path], history: bool, entropy_threshold: Optional[float]):
    """Non-interactively baseline all current secret findings (does not fail/exit non-zero)."""
    click.echo(f"[*] Scanning '{path}' to build a secrets baseline...")

    issues = _run_secrets_scan(path, config_path, history, staged_only=False, entropy_threshold=entropy_threshold)

    baseline_path = path / ".pyspector_baseline.json"
    existing_fingerprints = _load_ignored_fingerprints(baseline_path)
    fingerprints = existing_fingerprints | {issue.get_fingerprint() for issue in issues}

    baseline_path.write_text(
        json.dumps({"ignored_fingerprints": sorted(fingerprints)}, indent=2),
        encoding='utf-8',
    )

    click.echo(click.style(
        f"[+] Baseline saved to '{baseline_path}' with {len(fingerprints)} ignored finding(s).",
        fg="green",
    ))
    click.echo("[*] Run 'pyspector triage <report.json>' to interactively review or adjust the baseline later.")


_SECRETS_PRE_COMMIT_HOOK = """#!/bin/bash

# PySpector secret-detection pre-commit hook

echo "[PySpector] Scanning staged changes for secrets..."

pyspector secrets scan --staged-only --severity LOW

SCAN_RESULT=$?

if [ $SCAN_RESULT -ne 0 ]; then
    echo ""
    echo "[PySpector] Commit aborted: secret(s) detected in staged changes."
    echo "[PySpector] Review the findings above, remove the secret(s), or add them to .pyspector_baseline.json if they are false positives (see 'pyspector secrets baseline')."
    echo "[PySpector] To bypass in an emergency: git commit --no-verify (not recommended)."
    exit 1
fi

echo "[PySpector] No secrets found. Proceeding with commit."
exit 0
"""


@secrets.command(name="install-hook", help="Install a Git pre-commit hook that runs 'pyspector secrets scan --staged-only' before every commit.")
@click.option('--force', is_flag=True, help="Overwrite an existing pre-commit hook.")
def secrets_install_hook_command(force: bool):
    """Installs the secret-detection pre-commit hook into the current repository."""
    try:
        repo_root = Path(subprocess.run(
            ['git', 'rev-parse', '--show-toplevel'],
            check=True, capture_output=True, text=True,
        ).stdout.strip())
    except (subprocess.CalledProcessError, FileNotFoundError):
        click.echo(click.style("Error: Not inside a Git repository.", fg="red"))
        sys.exit(1)

    hook_path = repo_root / ".git" / "hooks" / "pre-commit"

    if hook_path.exists() and not force:
        click.echo(click.style(f"Error: '{hook_path}' already exists. Use --force to overwrite.", fg="red"))
        sys.exit(1)

    hook_path.parent.mkdir(parents=True, exist_ok=True)
    hook_path.write_text(_SECRETS_PRE_COMMIT_HOOK, encoding='utf-8', newline='\n')
    hook_path.chmod(hook_path.stat().st_mode | 0o111)

    click.echo(click.style(f"[+] Installed secret-detection pre-commit hook at '{hook_path}'.", fg="green"))


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


@click.command(
    help=(
        "Watch a directory or file and re-scan on every .py change.\n\n"
        "Runs a full initial scan on startup, then re-scans whenever a\n"
        ".py file is created, modified, or deleted. Only new and resolved\n"
        "findings are printed after each re-scan."
    )
)
@click.argument(
    "path",
    type=click.Path(
        exists=True, file_okay=True, dir_okay=True,
        readable=True, path_type=Path,
    ),
)
@click.option(
    "-s", "--severity", "severity_level",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    default="LOW", show_default=True,
    help="Minimum severity level to report.",
)
@click.option(
    "--ai", "ai_scan", is_flag=True, default=False,
    help="Enable specialized scanning for AI/LLM vulnerabilities.",
)
@click.option(
    "-c", "--config", "config_path",
    type=click.Path(exists=True, path_type=Path),
    help="Path to a pyspector.toml config file.",
)
@click.option(
    "--debounce", default=1.0, show_default=True, metavar="SECONDS",
    help="Wait this many seconds after the last change before re-scanning.",
)
@click.option(
    "--debug", is_flag=True, default=False,
    help="Show verbose progress output.",
)
def watch_command(
    path:           Path,
    severity_level: str,
    ai_scan:        bool,
    config_path:    Optional[Path],
    debounce:       float,
    debug:          bool,
) -> None:
    """Continuous watch mode: re-scan on every .py file change."""
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        click.echo(
            "Error: 'watchdog' is required for watch mode.\n"
            "Install it with:  pip install 'watchdog>=3.0'"
        )
        sys.exit(1)

    _print_banner()
    click.echo(f"[*] Watch mode  —  " + click.style(str(path), bold=True))
    click.echo(
        f"    Severity : {severity_level}"
        f"  |  AI rules : {'on' if ai_scan else 'off'}"
        f"  |  Debounce : {debounce}s"
        f"  |  Ctrl+C to stop\n"
    )

    _DIVIDER      = "─" * 62
    _BOLD_DIVIDER = "─" * 62

    # ── Shared mutable state (accessed from background timer threads) ─────
    cache   = get_cache(path)
    # Use containers so nested functions can mutate without `nonlocal`
    _state:   Dict[str, Any] = {"prev_fps": {}}  # fingerprint -> issue
    _changed: set             = set()
    _lock                     = threading.Lock()
    _pending: List            = [None]            # [Optional[threading.Timer]]

    # ── Initial full scan ─────────────────────────────────────────────────
    click.echo("[~] Running initial scan...")
    try:
        initial = _scan_to_issues(
            path, config_path, severity_level, ai_scan, debug=debug, cache=cache
        )
    except Exception as exc:
        click.echo(f"[!] Initial scan failed: {exc}")
        initial = []

    _state["prev_fps"] = {iss.get_fingerprint(): iss for iss in initial}

    if initial:
        click.echo(f"\n[!] Initial scan: {len(initial)} issue(s) found:")
        click.echo(Reporter(initial, "console").generate())
    else:
        click.echo("[+] Initial scan: clean — no issues found.")

    click.echo("\n[*] Watching for changes...\n")

    # ── Re-scan + diff ────────────────────────────────────────────────────
    def _do_rescan() -> None:
        with _lock:
            changed_snapshot = set(_changed)
            _changed.clear()
            _pending[0] = None

        ts = time.strftime("%H:%M:%S")
        if changed_snapshot:
            names = sorted(Path(p).name for p in changed_snapshot)
            label = ", ".join(names[:3]) + (
                f" (+{len(names) - 3} more)" if len(names) > 3 else ""
            )
        else:
            label = "re-scan"

        click.echo(_BOLD_DIVIDER)
        click.echo(f"[{ts}] " + click.style(label, bold=True))
        click.echo(_BOLD_DIVIDER)

        try:
            new_issues = _scan_to_issues(
                path, config_path, severity_level, ai_scan, debug=debug, cache=cache
            )
        except Exception as exc:
            click.echo(f"  [!] Scan error: {exc}")
            click.echo(_DIVIDER + "\n")
            return

        new_fps  = {iss.get_fingerprint(): iss for iss in new_issues}
        prev_fps = _state["prev_fps"]

        appeared = [iss for fp, iss in new_fps.items()  if fp not in prev_fps]
        resolved = [iss for fp, iss in prev_fps.items() if fp not in new_fps]

        if not appeared and not resolved:
            click.echo("  No change in findings.")
        else:
            for iss in appeared:
                click.echo(_fmt_watch_issue(iss, "NEW", "red"))
            for iss in resolved:
                click.echo(_fmt_watch_issue(iss, "RESOLVED", "green"))

        n_new = len(appeared)
        n_res = len(resolved)
        total = len(new_issues)
        click.echo(_DIVIDER)
        click.echo(
            f"  {click.style(f'Active: {total}', bold=True)}"
            f"  ·  +{n_new} new"
            f"  ·  -{n_res} resolved\n"
        )

        _state["prev_fps"] = new_fps

    # ── Debounce scheduler ────────────────────────────────────────────────
    def _schedule(file_path: str) -> None:
        with _lock:
            _changed.add(file_path)
            if _pending[0] is not None:
                _pending[0].cancel()
            t = threading.Timer(debounce, _do_rescan)
            _pending[0] = t
            t.start()

    # ── Watchdog handler: only cares about .py files ──────────────────────
    class _PyHandler(FileSystemEventHandler):
        def _dispatch(self, event) -> None:
            if event.is_directory:
                return
            for attr in ("src_path", "dest_path"):
                p = getattr(event, attr, "")
                if p and p.endswith(".py"):
                    _schedule(p)
                    return

        def on_modified(self, event) -> None: self._dispatch(event)
        def on_created(self,  event) -> None: self._dispatch(event)
        def on_deleted(self,  event) -> None: self._dispatch(event)
        def on_moved(self,    event) -> None: self._dispatch(event)

    watch_root = str(path if path.is_dir() else path.parent)
    observer   = Observer()
    observer.schedule(_PyHandler(), path=watch_root, recursive=True)
    observer.start()

    try:
        while observer.is_alive():
            observer.join(timeout=1.0)
    except KeyboardInterrupt:
        pass
    finally:
        with _lock:
            if _pending[0] is not None:
                _pending[0].cancel()
        observer.stop()
        observer.join()
        click.echo("\n[*] Watch mode stopped.")


# Add commands to the CLI group
cli.add_command(run_scan_command, name="scan")
cli.add_command(triage_command,   name="triage")
cli.add_command(plugin)
cli.add_command(secrets)
