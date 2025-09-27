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

1.  **Python**: You'll need Python 3.8 or newer (recommended Python3.12).
2.  **Rust**: The core engine of PySpector is written in Rust. The best way to install it is via [rustup](https://rustup.rs/).

### Development Setup

1.  **Fork Pyspector and Clone your Repository**:
    ```bash
    git clone https://github.com/YOURUSERNAME/PySpector.git
    cd PySpector
    ```

2.  **Create a Python3.12 Virtual Environment**:
    ```bash
    python3.12 -m venv venvname
    ```
Then:
    ```
    source venvname/bin/activate
    ```
or, if on Windows:
    ```
    .\venvname\Bin\Activate.ps1
    ```

3.  **Install the Project in Editable Mode**: This is the most important step. This command will compile the Rust engine and install the Python package in a way that lets you make changes without reinstalling.
    ```bash
    pip install -e .
    ```

4.  **Run it!**: You should now be able to run PySpector directly.
    ```bash
    pyspector --help
    ```

---

## 📝 Adding a New Rule

Adding a new rule is a great way to make a big impact. Rules are defined in the `.toml` files located in `src/pyspector/rules/`.

* **Simple Regex Rules**: For rules that can be found with a simple text search, you can add a new `[[rule]]` to `built-in-rules.toml`. Just define a `pattern` using a regular expression.
* **AST-Based Rules**: For more complex rules that need to understand the code's structure, you can define an `ast_match` pattern. This allows you to target specific Python AST nodes, like function calls with certain arguments.
* **Taint Analysis Rules**: To track the flow of untrusted data, you can define new `[[taint_source]]` or `[[taint_sink]]` rules.

When adding a new rule, please include a clear `description`, a `severity` level, and helpful `remediation` advice.

---

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

