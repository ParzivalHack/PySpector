<img width="2048" height="681" alt="image" src="https://github.com/user-attachments/assets/0093a5d2-d1c9-45dd-b129-2de196f3be1f" />



# High-Performance Python and Rust SAST Framework

[![POWERED BY](https://img.shields.io/badge/POWERED%20BY-SecurityCert-purple)](https://www.securitycert.it/)
[![Total PyPI Downloads](https://static.pepy.tech/badge/your-package-name)](https://pepy.tech/project/pyspector)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/pyspector?period=weekly&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=BLUE&left_text=Downloads%2Fweek)](https://pepy.tech/projects/pyspector)
[![latest release](https://img.shields.io/badge/latest%20release-v0.1.4--beta-blue)](https://github.com/ParzivalHack/PySpector/releases/tag/v0.1.4-beta-hotfix)
[![PyPI version](https://img.shields.io/pypi/v/pyspector?color=blue&label=pypi%20package)](https://pypi.org/project/pyspector/)
[![Python version](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Rust version](https://img.shields.io/badge/Rust-stable-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)


PySpector is a static analysis security testing (SAST) Framework engineered for modern Python development workflows. It leverages a powerful Rust core to deliver high-speed, accurate vulnerability scanning, wrapped in a developer-friendly Python CLI. By compiling the analysis engine to a native binary, PySpector avoids the performance overhead of traditional Python-based tools, making it an ideal choice for integration into CI/CD pipelines and local development environments where speed is critical.

The tool is designed to be both comprehensive and intuitive, offering a multi-layered analysis approach that goes beyond simple pattern matching to understand the structure and data flow of your application.



## Getting Started

### Prerequisites

-   **Python**: Version 3.12 or lower (Python 3.9+ required).
-   **Rust**: The Rust compiler (`rustc`) and Cargo package manager are required. You can easily install the **Rust toolchain** via [rustup](https://rustup.rs/) and verify your installation by running `cargo --version`.

### Installation

1.  **Create a Virtual Environment**: It is highly recommended to install PySpector in a dedicated Python3.12 venv.
    ```bash
    python3.12 -m venv venv
    source venv/bin/activate
    ```
* In Windows, just download Python 3.12 from the Microsoft Store and run:
```powershell
    python3.12 -m venv venv
    .\venv\Scripts\Activate.ps1
    # or, depending on the Python3.12 installation source: .\venv\bin\Activate.ps1
```

With PySpector now officially on PyPI(🎉), installation is as simple as running:

```bash
pip install pyspector
```

## Key Features

* **Multi-Layered Analysis Engine:** PySpector employs a sophisticated, multi-layered approach to detect a broad spectrum of vulnerabilities:

* * **Regex-Based Pattern Matching:** Scans all files for specific patterns, ideal for identifying hardcoded secrets, insecure configurations in Dockerfiles, and weak settings in framework files.

* * **Abstract Syntax Tree (AST) Analysis:** For Python files, the tool parses the code into an AST to analyze its structure. This enables precise detection of vulnerabilities tied to code constructs, such as the use of eval(), insecure deserialization with pickle, or weak hashing algorithms.

* * **Inter-procedural Taint Analysis:** The engine builds a comprehensive call graph of the entire application to perform taint analysis. It tracks the flow of data from input sources (like web requests) to dangerous sinks (like command execution functions), allowing it to identify complex injection vulnerabilities with high accuracy.

* **Comprehensive and Customizable Ruleset:** PySpector comes with 241 built-in rules that cover common vulnerabilities, including those from the OWASP Top 10. The rules are defined in a simple TOML format, making them easy to understand and extend.

* **Versatile Reporting:** Generates clear and actionable reports in multiple formats, including a developer-friendly console output, JSON, HTML, and SARIF for seamless integration with other security tools and platforms.

* **Efficient Baselining:** The interactive triage mode simplifies the process of establishing a security baseline, allowing teams to focus on new and relevant findings in each scan.

## How It Works

PySpector's hybrid architecture is key to its performance and effectiveness.

* **Python CLI Orchestration:** The process begins with the Python-based CLI. It handles command-line arguments, loads the configuration and rules, and prepares the target files for analysis. For each Python file, it uses the native ast module to generate an Abstract Syntax Tree, which is then serialized to JSON.

* **Invocation of the Rust Core:** The serialized ASTs, along with the ruleset and configuration, are passed to the compiled Rust core. The handoff from Python to Rust is managed by the pyo3 library.

* **Parallel Analysis in Rust:** The Rust engine takes over and performs the heavy lifting. It leverages the rayon crate to execute file scans and analysis in parallel, maximizing the use of available CPU cores. It builds a complete call graph of the application to understand inter-file function calls, which is essential for the taint analysis module.

* **Results and Reporting:** Once the analysis is complete, the Rust core returns a structured list of findings to the Python CLI. The Python wrapper then handles the final steps of filtering the results based on the severity threshold and the baseline file, and generating the report in the user-specified format.

This architecture combines the best of both worlds: a flexible, user-friendly interface in Python and a high-performance, memory-safe analysis engine in Rust :)

## Performance Benchmarks

Performance benchmarks demonstrate PySpector's competitive advantages in SAST scanning speed while maintaining comprehensive security analysis.

> Performance benchmarks were executed in a deterministic and controlled environment using automated stress-testing scripts, ensuring repeatable and unbiased measurements

### Benchmark Results

<img width="4471" height="3529" alt="speed_benchmark_charts" src="https://github.com/user-attachments/assets/9ca0cd7a-82eb-4365-b5c3-94a60eb6d3d9" />


#### Comparative analysis across major Python codebases (Django, Flask, Pandas, Scikit-learn, Requests) shows:

| Metric | PySpector | Bandit | Semgrep |
|--------|-----------|---------|---------|
| **Throughput** | 25,607 lines/sec | 14,927 lines/sec | 1,538 lines/sec |
| **Performance Advantage** | **71% faster** than Bandit | Baseline | 16.6x slower |
| **Memory Usage** | 1.4 GB average | 111 MB average | 277 MB average |
| **CPU Utilization** | 120% (multi-core) | 100% (single-core) | 40% |

### Key Performance Characteristics

- **Speed**: Delivers 71% faster scanning than traditional tools through Rust-powered parallel analysis
- **Scalability**: Maintains high throughput on large codebases (500k+ lines of code)
- **Resource Profile**: Optimized for modern multi-core environments with adequate memory allocation
- **Consistency**: Stable performance across different project types and sizes

### System Requirements for Optimal Performance

- **Minimum**: 2 CPU cores, 2 GB RAM
- **Recommended**: 4+ CPU cores, 4+ GB RAM for large codebases
- **Storage**: SSD recommended for large repository scanning

### Benchmark Methodology

Performance testing conducted on:
- **Test Environment**: Debian-based Linux VM (2 cores, 4GB RAM)
- **Test Projects**: 5 major Python repositories (13k-530k lines of code)
- **Measurement**: Average of multiple runs with CPU settling periods
- **Comparison**: Head-to-head against Bandit and Semgrep using identical configurations

*Benchmark data available in the project repository for transparency and reproducibility.*

## Usage

PySpector is operated through a straightforward command-line interface.

### Running a Scan

The primary command is `scan`, which can target a local file, a directory, or even a remote Git repository.

```bash
pyspector scan [PATH or --url REPO_URL] [OPTIONS]
```

### Examples:

* **Scan a single file**
```bash
pyspector scan project/main.py
```

* **Scan a local directory and save the report as HTML:**
```bash
pyspector scan /path/to/your/project -o report.html -f html
```

* **Scan a public GitHub repository:**
```bash
pyspector scan --url https://github.com/username/repo.git
```

### Scan for AI and LLM Vulnerabilities

<img width="970" height="1096" alt="image" src="https://github.com/user-attachments/assets/14bac1c0-eae2-4dab-ab40-8047b46bbac8" />


* **Use the `--ai` flag to enable a specialized ruleset, for projects using Large Language Models:**

```bash
pyspector scan /path/to/your/project --ai
```

## Plugin System (NEW FEATURE🚀)
<img width="1298" height="538" alt="image" src="https://github.com/user-attachments/assets/f2ad2a5e-c8e3-4723-a729-f318fef07e24" />
PySpector ships with an extensible plugin architecture that lets you post-process findings, generate custom artefacts, or orchestrate follow-up actions after every scan. Plugins run in-process once the Rust core returns the final issue list, so they see exactly the same normalized data that drives the built-in reports.

### Lifecycle Overview

1. **Discovery** - Plugin files live in the repository's `plugins` directory (`PySpector/plugins`) and are discovered automatically.  
2. **Registration** - Trusted plugins are recorded in `PySpector/plugins/plugin_registry.json` together with their checksum and metadata.  
3. **Validation** - Before execution PySpector validates plugin configuration, statically inspects the source for dangerous APIs, and checks the on-disk checksum.  
4. **Execution** - The plugin is initialized, receives the full findings list, and can emit additional files or data. `cleanup()` is always called at the end.

### Managing Plugins from the CLI

The CLI exposes helper commands for maintaining your local catalogue:

```bash
pyspector plugin list               # Show discovered plugins, trust status, version, author
pyspector plugin trust plugin_name     # Validate, checksum, and mark a plugin as trusted
pyspector plugin info plugin_name     # Display stored metadata and checksum verification
pyspector plugin install path/to/plugin.py --trust
pyspector plugin remove legacy_plugin
```

Only trusted plugins are executed automatically. When you trust a plugin PySpector calculates its SHA256 checksum and stores the version, author, and description that the plugin declares via `PluginMetadata`. If the file is modified later you will be warned before it runs again. To trust a plugin:

```bash
pyspector plugin install ./PySpector/plugins/aipocgen.py --trust
```

### Running Plugins During a Scan

Use one or more `--plugin` flags during `pyspector scan` and provide a JSON configuration file if the plugin expects custom settings:

```bash
pyspector scan vulnerableapp.py --plugin aipocgen --plugin-config ./PySpector/pluginconfig/aipocgen.json
```

The configuration file must be a JSON object whose keys match plugin names, for example:

```json
{
  "aipocgen": {
    "api_key": "YOUR-GROQ-KEY",
    "model": "llama-3.3-70b",
    "severity_filter": ["HIGH", "CRITICAL"],
    "max_pocs": 5,
    "output_dir": "pocs",
    "dry_run": false
  }
}
```

Each plugin receives only its own configuration block. Results are printed in the CLI, and any paths returned in the `output_files` list are shown under “Generated files”.

### Authoring a Plugin

Create a new Python file in `~/.pyspector/plugins/<name>.py` and subclass `PySpectorPlugin`:

```python
from pathlib import Path
from typing import Any, Dict, List

from pyspector.plugin_system import PySpectorPlugin, PluginMetadata


class MyPlugin(PySpectorPlugin):
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="my_plugin",
            version="0.1.0",
            author="Your Name",
            description="Summarises HIGH severity findings",
            category="reporting",
        )

    def validate_config(self, config: Dict[str, Any]) -> tuple[bool, str]:
        if "output_file" not in config:
            return False, "output_file is required"
        return True, ""

    def initialize(self, config: Dict[str, Any]) -> bool:
        self.output = Path(config["output_file"]).resolve()
        return True

    def process_findings(
        self,
        findings: List[Dict[str, Any]],
        scan_path: Path,
        **kwargs,
    ) -> Dict[str, Any]:
        highs = [f for f in findings if f.get("severity") == "HIGH"]
        self.output.write_text(f"{len(highs)} HIGH findings\n", encoding="utf-8")
        return {
            "success": True,
            "message": f"Summarised {len(highs)} HIGH findings",
            "output_files": [str(self.output)],
        }
```

Your plugin must implement the following:

- **`metadata`** – Return a `PluginMetadata` instance describing the plugin.  
- **`validate_config(config)`** *(optional but recommended)* – Abort gracefully when required settings are missing by returning `(False, "reason")`.  
- **`initialize(config)`** – Prepare state or dependencies; return `False` to skip execution.  
- **`process_findings(findings, scan_path, **kwargs)`** – Receive every finding as a dictionary and return a result object containing:
  - `success`: boolean status
  - `message`: short summary for the CLI
  - `data`: optional serializable payload
  - `output_files`: optional list of generated file paths
- **`cleanup()`** *(optional)* – Release resources; called even if an exception occurs.

Tip: Plugins are plain Python modules, so you can run `python my_plugin.py` while developing to perform quick checks before trusting them through the CLI.

### Configuration Tips and Best Practices

- Store API keys or long-lived secrets in environment variables and read them during `initialize`. Provide helpful error messages when credentials are missing.  
- Keep side-effects inside the scan directory. When PySpector scans a single file `scan_path` is that file, so the reference plugins switch to `scan_path.parent` before writing outputs.  
- Validate configuration early using `validate_config`; PySpector surfaces the error message in the CLI without executing the plugin.  
- Return meaningful `message` values and populate `output_files` so automation can pick up generated artifacts.  
- Document optional switches such as `dry_run` (see the bundled `aipocgen` plugin for an example) to support air-gapped testing.

### Security Model

The plugin manager enforces several safeguards:

- **AST-based static inspection** blocks dangerous constructs (`eval`, `exec`, `subprocess.*`, etc.) and prints warnings when sensitive but acceptable calls (e.g., `open`) are used.  
- **Trust workflow** – you must explicitly trust a plugin before it can run; the CLI informs you about any warnings produced during validation.  
- **Checksum verification** – each trusted plugin has a stored SHA256 hash; changes are flagged before execution.  
- **Argument isolation** – the runner resets `sys.argv` to a minimal value so Click-based plugins cannot consume the parent CLI arguments accidentally.  
- **Structured error handling** – exceptions are caught, traced, and reported without aborting the main scan, and `cleanup()` still runs.

Together these measures let you extend PySpector confidently while maintaining a secure supply chain for third-party automation.

## Triaging and Baselining Findings

<img width="871" height="950" alt="image" src="https://github.com/user-attachments/assets/8ad8e8b9-528a-426f-96e3-c0a66c2c683d" />


PySpector includes an interactive triage mode to help manage and baseline findings. This allows you to review issues and mark them as "ignored" so they don't appear in future scans.

* **Generate a JSON report:**
```bash
pyspector scan /path/to/your/project -o report.json -f json
```

* **Start the triage TUI:**
```bash
pyspector triage report.json
```

Inside the TUI, you can navigate with the arrow keys, press i to toggle the "ignored" status of an issue, and s to save your changes to a .pyspector_baseline.json file. This baseline file will be automatically loaded on subsequent scans.

## Automation and Integration

PySpector includes Shell helper scripts to integrate security scanning directly into your development and operational workflows.

### Git Pre-Commit Hook

To ensure that no new high-severity issues are introduced into the codebase, you can set up a Git pre-commit hook. This hook will automatically scan staged Python files before each commit and block the commit if any HIGH or CRITICAL issues are found.

**To set up the hook, run the following script from the root of your Git repository:**
```bash
./scripts/setup_hooks.sh
```
This script creates an executable .git/hooks/pre-commit file that performs the check. You can bypass the hook for a specific commit by using the --no-verify flag with your git commit command.

## Scheduled Scans with Cron

For continuous monitoring, you can schedule regular scans of your projects using a cron job. PySpector provides an interactive script to help you generate the correct crontab entry.

**To generate your cron job command, run:**
```bash
./scripts/setup_cron.sh
```
The script will prompt you for the project path, desired scan frequency (daily, weekly, monthly), and a location to store the JSON reports. It will then output the command to add to your crontab, automating your security scanning and reporting process.
