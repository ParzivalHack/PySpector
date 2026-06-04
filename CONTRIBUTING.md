<div id="header" align="center">
  <img src="https://media.giphy.com/media/YRMb6dd7zprS00JdGZ/giphy.gif" width="100"/>
</div>

# Contributing to PySpector

First off, thank you for considering contributing to PySpector! We're excited to have you. Every contribution, whether it's a new feature, a bug fix, or a new rule, helps us make Python code, safer for everyone.

This document provides a simple guide to get you started.

---

## 💡 How Can I Contribute?

There are many ways you can contribute to the project:

* **Reporting Bugs**: If you find something that isn't working as expected, please [open an issue](https://github.com/ParzivalHack/PySpector/issues).
* **Suggesting Enhancements**: Have an idea for a new feature or a way to improve an existing one? We'd love to hear it.
* **Writing New Rules**: The heart of PySpector is its ruleset. Adding new rules to detect vulnerabilities is one of the most valuable ways to contribute.
* **Improving the Code**: If you see an opportunity to improve the Python or Rust code, feel free to [submit a PR](https://github.com/ParzivalHack/PySpector/pulls).

---

## 🚀 Getting Started

To get the project running on your local machine, you'll need to set up a few things.

### Prerequisites

1.  **Python**: Python 3.9 or newer is required (Python 3.14 is recommended). You can check your Python version by running `python --version`.
2.  **Rust**: The core engine of PySpector is written in Rust. Install it via [rustup](https://rustup.rs/) and verify with `rustc --version` and `cargo --version`.

### Development Setup

1.  **Fork Pyspector and Clone your Repository**:
    ```bash
    git clone https://github.com/YOURUSERNAME/PySpector.git
    cd PySpector
    ```

2.  **Create a Python 3.14 Virtual Environment**:

    **On Linux/macOS (Bash)**:
    ```bash
    python3.14 -m venv venv
    source venv/bin/activate
    ```

    **On Windows (PowerShell)**:
    ```powershell
    python3.14 -m venv venv
    .\venv\Scripts\Activate.ps1
    ```

3.  **Install the Project in Editable Mode**: This is the most important step. This command will compile the Rust engine and install the Python package in a way that lets you make changes without reinstalling.
    ```bash
    pip install -e .
    ```

4.  **Verify the Installation**: You should now be able to run PySpector directly.
    ```bash
    pyspector --help
    ```

---

## 🧪 Testing and Development

Before submitting a PR, please ensure your code passes tests and adheres to code quality standards.

### Running Tests

Run the unit tests using Python's unittest framework:
```bash
python -m unittest discover tests/unit -v
```

Or run a specific test file:
```bash
python -m unittest tests.unit.test_ai_rules -v
```

### Code Quality

The project uses **Ruff** for linting and code formatting. Install it if not already included:
```bash
pip install ruff
```

**Check for linting issues**:
```bash
ruff check src/
```

**Auto-format your code**:
```bash
ruff format src/
```

**Fix common issues automatically**:
```bash
ruff check --fix src/
```

### Type Checking

The project uses **MyPy** for type checking. Ensure your code has proper type hints:
```bash
mypy src/
```

### Before Submitting a PR

Run this checklist to ensure your changes are ready:

1. **Install in editable mode**: `pip install -e .` (compiles Rust engine)
2. **Run all tests**: `python -m unittest discover tests/unit -v`
3. **Check linting**: `ruff check src/`
4. **Format code**: `ruff format src/`
5. **Run type checks**: `mypy src/`

Fix any issues found before pushing your changes.

---

## 📝 Adding a New Rule

Adding a new rule is a great way to make a big impact. Rules are defined in the `.toml` files located in `src/pyspector/rules/`.

* **Simple Regex Rules**: For rules that can be found with a simple text search, you can add a new `[[rule]]` to `built-in-rules.toml`. Just define a `pattern` using a regular expression.
* **AST-Based Rules**: For more complex rules that need to understand the code's structure, you can define an `ast_match` pattern. This allows you to target specific Python AST nodes, like function calls with certain arguments.
* **Taint Analysis Rules**: To track the flow of untrusted data, you can define new `[[taint_source]]` or `[[taint_sink]]` rules.

When adding a new rule, please include a clear `description`, a `severity` level, and helpful `remediation` advice.

---

## Writing Custom Rules

PySpector rules define *what* the engine looks for during analysis. Each rule describes a pattern or behavior that represents a potential security issue.

A rule typically consists of:
- Metadata (name, severity, description)
- A matcher or condition
- A message explaining the issue

Rules are loaded at runtime and applied uniformly across the scanned codebase.

### Minimal Example

Below is a minimal conceptual example of a rule:

```toml
file_pattern = "*.py"

[[rule]]
id = "PY200"
description = "Use of 'eval' detected."
severity = "High"
remediation = "Avoid using eval(). Use safer alternatives like ast.literal_eval or explicit parsing."
ast_match = "Call(func.id=eval)"
```


## ✅ Submitting Your Contribution

Ready to submit your changes? Just follow these steps:

1.  **Create a new branch** for your feature or bug fix.
    ```bash
    git checkout -b my-new-rule
    ```
2.  **Make your changes** and commit them with a clear message.
    ```bash
    git commit -m "feat: Add new rule to detect insecure cookie settings"
    ```
3.  **Push your branch** to your fork.
    ```bash
    git push origin my-new-rule
    ```
4.  [**Open a Pull Request**](https://github.com/ParzivalHack/PySpector/pulls) on the main PySpector repository. Please provide a clear description of what you've done.

We'll review your contribution as soon as we can. Thank you again for considering helping to improve PySpector!

