import click
import time
import json
import ast
import subprocess
import tempfile
import sys
from pathlib import Path
from typing import Optional, Dict, Any, List, cast

from .config import load_config, get_default_rules
from .reporting import Reporter
from .triage import run_triage_tui

# Import the Rust core from its new location
try:
    from pyspector._rust_core import run_scan
except ImportError:
    click.echo(click.style("Error: PySpector's core engine module not found.", fg="red"))
    exit(1)

# --- Helper function for AST serialization ---
class AstEncoder(json.JSONEncoder):
    def default(self, node):
        if isinstance(node, ast.AST):
            fields = {
                "node_type": node.__class__.__name__,
                "lineno": getattr(node, 'lineno', -1),
                "col_offset": getattr(node, 'col_offset', -1),
            }
            # Separate fields from children nodes for clarity in Rust
            child_nodes = {}
            simple_fields = {}
            for field, value in ast.iter_fields(node):
                if isinstance(value, list) and all(isinstance(n, ast.AST) for n in value):
                    child_nodes[field] = value
                elif isinstance(value, ast.AST):
                    child_nodes[field] = [value]
                else:
                    # Handle non-JSON serializable types
                    if isinstance(value, bytes):
                        simple_fields[field] = value.decode('utf-8', errors='replace')
                    elif isinstance(value, (int, float, str, bool, type(None))):
                        simple_fields[field] = value
                    else:
                        # Convert other types to string representation
                        simple_fields[field] = str(value)
            
            fields["children"] = child_nodes
            fields["fields"] = simple_fields
            return fields
        elif isinstance(node, bytes):
            return node.decode('utf-8', errors='replace')
        elif hasattr(node, '__dict__'):
            # Handle other objects that might not be JSON serializable
            return str(node)
        return super().default(node)

def get_python_file_asts(path: Path) -> List[Dict[str, Any]]:
    """Recursively finds Python files and returns their content and AST."""
    results = []
    files_to_scan = list(path.glob('**/*.py')) if path.is_dir() else [path]

    for py_file in files_to_scan:
        if py_file.is_file():
            try:
                content = py_file.read_text(encoding='utf-8')
                parsed_ast = ast.parse(content, filename=str(py_file))
                ast_json = json.dumps(parsed_ast, cls=AstEncoder)
                results.append({
                    "file_path": str(py_file),
                    "content": content,
                    "ast_json": ast_json
                })
            except (SyntaxError, UnicodeDecodeError) as e:
                click.echo(click.style(f"Warning: Could not parse {py_file}: {e}", fg="yellow"))
    return results

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
    click.echo("Version: 0.1.2-beta\n")
    click.echo("Made with <3 by github.com/ParzivalHack\n")

cli = cast(click.Group, cli)

@click.command(help="Scan a directory, file, or remote Git repository for vulnerabilities.")
@click.argument('path', type=click.Path(exists=True, file_okay=True, dir_okay=True, readable=True, path_type=Path), required=False)
@click.option('-u', '--url', 'repo_url', type=str, help="URL of a public GitHub/GitLab repository to clone and scan.")
@click.option('-c', '--config', 'config_path', type=click.Path(exists=True, path_type=Path), help="Path to a pyspector.toml config file.")
@click.option('-o', '--output', 'output_file', type=click.Path(path_type=Path), help="Path to write the report to.")
@click.option('-f', '--format', 'report_format', type=click.Choice(['console', 'json', 'sarif', 'html']), default='console', help="Format of the report.")
@click.option('-s', '--severity', 'severity_level', type=click.Choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']), default='LOW', help="Minimum severity level to report.")
@click.option('--ai', 'ai_scan', is_flag=True, default=False, help="Enable specialized scanning for AI/LLM vulnerabilities.")
def run_scan_command(path: Optional[Path], repo_url: Optional[str], config_path: Optional[Path], output_file: Optional[Path], report_format: str, severity_level: str, ai_scan: bool):
    """The main scan command."""
    if not path and not repo_url:
        raise click.UsageError("You must provide either a PATH or a --url to scan.")
    if path and repo_url:
        raise click.UsageError("You cannot provide both a PATH and a --url.")

    if repo_url:
        # Handle Git URL cloning
        if not ("github.com" in repo_url or "gitlab.com" in repo_url):
            raise click.BadParameter("URL must be a public GitHub or GitLab repository.")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            click.echo(f"[*] Cloning '{repo_url}' into temporary directory...")
            try:
                subprocess.run(
                    ['git', 'clone', '--depth', '1', repo_url, temp_dir],
                    check=True,
                    capture_output=True,
                    text=True
                )
                scan_path = Path(temp_dir)
                _execute_scan(scan_path, config_path, output_file, report_format, severity_level, ai_scan)
            except subprocess.CalledProcessError as e:
                click.echo(click.style(f"Error: Failed to clone repository.\n{e.stderr}", fg="red"))
                sys.exit(1)
            except FileNotFoundError:
                click.echo(click.style("Error: 'git' command not found. Please ensure Git is installed and in your PATH.", fg="red"))
                sys.exit(1)
    else:
        # Handle local path scan
        scan_path = path
        _execute_scan(scan_path, config_path, output_file, report_format, severity_level, ai_scan)


def _execute_scan(scan_path: Path, config_path: Optional[Path], output_file: Optional[Path], report_format: str, severity_level: str, ai_scan: bool):
    """Helper function to run the actual scan and reporting."""
    start_time = time.time()
    
    config = load_config(config_path)
    rules_toml_str = get_default_rules(ai_scan)

    click.echo(f"[*] Starting PySpector scan on '{scan_path}'...")
    
    # --- Load Baseline ---
    baseline_path = scan_path / ".pyspector_baseline.json" if scan_path.is_dir() else scan_path.parent / ".pyspector_baseline.json"
    ignored_fingerprints = set()
    if baseline_path.exists():
        try:
            with baseline_path.open('r') as f:
                baseline_data = json.load(f)
                ignored_fingerprints = set(baseline_data.get("ignored_fingerprints", []))
                click.echo(f"[*] Loaded baseline from '{baseline_path}', ignoring {len(ignored_fingerprints)} known issues.")
        except json.JSONDecodeError:
            click.echo(click.style(f"Warning: Could not parse baseline file '{baseline_path}'.", fg="yellow"))
    
    # --- AST Generation for Python files ---
    python_files_data = get_python_file_asts(scan_path)
    
    # --- Run Scan ---
    try:
        raw_issues = run_scan(str(scan_path.resolve()), rules_toml_str, config, python_files_data)
    except Exception as e:
        click.echo(click.style(f"Fatal error in scan engine: {e}", fg="red"))
        return

    # --- Filter by Severity and Baseline ---
    severity_map = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
    min_severity_val = severity_map[severity_level.upper()]

    final_issues = [
        issue for issue in raw_issues
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
    click.echo(f"\n[*] Scan finished in {end_time - start_time:.2f} seconds. Found {len(final_issues)} issues.")
    if len(raw_issues) > len(final_issues):
        click.echo(f"[*] Ignored {len(raw_issues) - len(final_issues)} issues based on severity level or baseline.")

@click.command(help="Start the interactive TUI to review and baseline findings.")
@click.argument('report_file', type=click.Path(exists=True, readable=True, path_type=Path))
def triage_command(report_file: Path):
    """The TUI command for baselining."""
    if not report_file.name.endswith('.json'):
        click.echo(click.style("Error: Triage mode only supports JSON report files generated by PySpector.", fg="red"))
        return

    try:
        with report_file.open('r', encoding='utf-8') as f:
            issues_data = json.load(f)
        
        # Determine baseline path relative to the report file
        baseline_path = report_file.parent / ".pyspector_baseline.json"
        
        run_triage_tui(issues_data.get("issues", []), baseline_path)

    except (json.JSONDecodeError, IOError) as e:
        click.echo(click.style(f"Error reading report file: {e}", fg="red"))

# Add the commands to the CLI group
cli.add_command(run_scan_command, name="scan")
cli.add_command(triage_command, name="triage")