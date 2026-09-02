---
name: pyspector-security-audit
description: Run a full Python codebase security audit using PySpector (https://github.com/ParzivalHack/PySpector), a Rust-core SAST scanner. Use this skill whenever the user asks for a security audit, vulnerability scan, SAST scan, code security review, or dependency/CVE check of a Python codebase or repository, including phrasing like "check this repo for vulnerabilities," "is my code secure," "audit my project," "scan for CVEs," or "find security issues." Also trigger if the user mentions PySpector by name for any reason (install, upgrade, run, configure). This skill installs PySpector (including its required Rust toolchain) if missing, selects scan flags based on what the codebase actually looks like, runs the scan, verifies findings against the real source before reporting them, and produces a report the user can read. Do not use this skill for non-Python codebases, for generic code review unrelated to security, or for fixing/patching vulnerabilities after the report already exists (that's a normal coding task).
---

# PySpector Security Audit

Drive an end-to-end Python codebase security audit with PySpector: install, verify, learn the CLI, recon the codebase, scan with the right flags, verify, report.

PySpector is a Rust-core, Python-CLI SAST tool with a flow-sensitive, inter-procedural taint engine. Its ruleset spans regex (secrets/config), AST (anti-patterns), and graph/taint (data-flow vulnerability chains), plus optional AI/LLM-specific rules and dependency CVE checks. Full project context: https://github.com/ParzivalHack/PySpector

## Workflow overview

1. Check for an existing install; install if missing (including Rust)
2. Confirm the install actually works
3. Read `pyspector --help` and `pyspector scan --help` to get the real, current flag set. Never assume flags from this document alone
4. Recon the target codebase to decide which optional rulesets apply
5. Run the scan(s) with the right flags
6. Statically re-verify the findings that matter before reporting anything
7. Produce the report (HTML for a human, JSON if something downstream will parse it) and only show the user verified true positives

Treat steps 3 and 4 as mandatory even if you already "know" PySpector's flags from a previous run. The tool evolves, and `--help` output is ground truth. Never fabricate a flag that didn't show up in `--help`.

## Step 1: Check for / install PySpector

Check first:

```bash
pyspector --version || pip show pyspector
```

If it's missing, PySpector's own docs say the supported path is PyPI, not manual OS-specific binary downloads. There's no separate per-OS release artifact to fetch; `pip install pyspector` builds/pulls the right thing for the current platform. So "install it based on the OS the agent is running on" in practice means: pick the right shell/venv invocation for the OS, not a different download URL.

**Rust toolchain (hard requirement).** PySpector's Rust core means `rustc` and `cargo` must be present, the project's own FAQ states this explicitly. Check first, install only if missing.

On Linux/macOS:

```bash
cargo --version || (curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source "$HOME/.cargo/env")
```

On Windows: first check whether `rustc`/`cargo` are already available. If not, check whether a `rustup-init.exe` installer is already present on the system (e.g. in the user's Downloads folder or a known path); if it is, run it. If no installer is present and you don't have shell access to the user's machine to download and run one yourself, don't try to fetch and execute an installer silently: direct the user to https://rustup.rs/ and ask them to download and run it themselves, then confirm back with you once it's done so you can proceed to verification.

**Python.** PySpector supports Python 3.9 to 3.14. The project recommends a dedicated venv (3.14 if available, but any supported version works):

```bash
python3 -m venv venv
source venv/bin/activate   # Windows: .\venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install pyspector
```

If a venv isn't appropriate for the environment you're in (e.g. an ephemeral agent sandbox), a plain `pip install pyspector --break-system-packages` (Linux) or `pip install pyspector` is fine. The venv is a recommendation for the human workflow, not a functional requirement for the scan itself.

## Step 2: Verify the install

Don't proceed on faith. Confirm all of:

```bash
rustc --version
cargo --version
python3 --version
pyspector --version
```

If any of these fail, stop and fix it before scanning. A broken Rust toolchain in particular will surface as a cryptic scan failure later rather than a clean error at install time.

## Step 3: Learn the current CLI

Always run these before scanning, even if you recall the flags from a previous session, and treat their output as the only source of truth for what flags exist and what they do:

```bash
pyspector --help
pyspector scan --help
```

Do not hardcode or assume a flag list. Parse whatever the live output actually shows: available options, their exact spelling, defaults, and descriptions. If something in this skill (like the decision rules below referencing `--ai` or `--supply-chain`) doesn't match what `--help` shows, trust `--help`.

Two commands surfaced by `pyspector --help` are interactive-only and out of scope for this skill's autonomous workflow:

- `pyspector triage <report.json>`: an interactive TUI for a human to mark findings as false positives and save a `.pyspector_baseline.json`. Don't invoke this yourself; if the user wants to triage findings interactively, tell them to run it themselves in their own terminal. If a baseline file already exists in the repo root from a prior human triage session, subsequent scans will pick it up automatically and suppress previously dismissed findings.
- `pyspector watch <path>`: continuous re-scan on file change, meant for a human to run in their own terminal during active development. Don't invoke this yourself; if relevant, tell the user they can run it themselves.

## Step 4: Recon the codebase before choosing flags

Before scanning, spend a short pass understanding what you're actually looking at, then pick flags accordingly using whatever flags Step 3 actually confirmed exist. Don't just run a bare default scan.

Checks to run:

```bash
# Age / maturity signals
git log -1 --format=%cd 2>/dev/null   # last commit date, if it's a git repo
find . -name "requirements*.txt" -o -name "pyproject.toml" -o -name "Pipfile*" -o -name "poetry.lock" | head

# Dependency pinning style (unpinned or very old pins : higher supply-chain risk)
cat requirements.txt 2>/dev/null || cat pyproject.toml 2>/dev/null

# AI/LLM usage signals
grep -RIl -E "openai|anthropic|langchain|llama[_-]index|transformers|litellm|ollama|cohere|google\.generativeai|vertexai" --include="*.py" . 2>/dev/null | head
```

Decision rules (apply these, and combine flags freely, they're not mutually exclusive):

- **Any signal of LLM/AI usage** (imports above, or the codebase *is* a model-serving/agent project) : add the AI ruleset flag. Running it even when unsure is fine; the cost of an unnecessary ruleset is low.
- **Old codebase, unpinned/loosely-pinned dependencies, no lockfile, or clear supply-chain risk signals** : the supply-chain CVE check flag is a good fit. This flag contacts the OSV.dev database directly to check dependencies against known CVEs, so it's not purely local and can very slightly increase scan time, on the order of a few seconds at most even on large codebases with many dependencies.
- **When it's genuinely unclear whether supply-chain checking is warranted** : don't default to including it. Ask the user first, and mention that it queries OSV.dev and may add a small amount of time (up to a few seconds on large projects with many dependencies) to the scan.
- **Large codebases** : not a concern by default. PySpector's Rust core comfortably handles very large codebases (hundreds of thousands of lines) at high throughput, so don't hesitate to run a full scan regardless of size.
- **First scan of a given codebase vs. later scans** : PySpector caches the AST it builds during a scan, so the first scan of a given codebase will always take somewhat longer than later ones. Subsequent scans are substantially faster, even after the source has changed somewhat in the meantime. If you're re-scanning something you already scanned earlier in the session, mention that it should be quicker this time; if it's a first scan, mention that this initial pass is expected to take a bit longer than future ones.

Set severity threshold based on intent: for a genuine security audit, use the lowest severity threshold (see what `--help` shows as the default/lowest option) to see everything, then let the verification step (Step 6) do the filtering. Don't pre-filter by raising the severity threshold, since that would hide true positives from your own verification pass, not just noise.

## Step 5: Run the scan

Always emit JSON as the primary artifact, you need structured output to parse and verify findings programmatically. Generate HTML at the end for the human, from the same run or a parallel run with identical flags.

For a remote repository instead of a local path, PySpector's `--url` option works only with **public** GitHub and GitLab repositories. It cannot pull from private repos or other git hosts, so confirm the repo is public before relying on this path; if it's private, ask the user for local access to the code instead (a local clone or an uploaded copy).

Don't default to SARIF output for this workflow. SARIF exists for CI/CD ingestion into platforms like GitHub Code Scanning, which isn't the context here (per PySpector's own docs on SARIF). If the user says the output specifically needs to feed a downstream tool that expects SARIF, honor that instead, but default to JSON and HTML.

## Step 6: Verify findings before reporting (static re-verification)

This is the step that turns "a scanner ran" into "a security audit." Do not hand the user PySpector's raw output as-is. SAST tools, PySpector included, will produce some false positives, especially on complex taint chains or when a sanitizer isn't recognized.

For every finding at MEDIUM severity or above (adjust the threshold down if the codebase is small enough to review everything):

1. Open the actual flagged file at the actual flagged line(s) in the real codebase. Don't reason from the finding's description alone
2. Trace the taint path the finding claims: confirm the source is genuinely attacker/externally-influenced input, and that it genuinely reaches the sink PySpector flagged
3. Check for a sanitizer, validation, or escaping step between source and sink that the finding's summary doesn't account for
4. Check surrounding context: is this dead code, a test fixture, or behind an auth/permission check that changes the real-world exploitability?
5. For supply-chain (CVE) findings: confirm the installed/pinned version in the dependency file actually matches the vulnerable range the CVE applies to, not just that the package name matched
6. Classify each reviewed finding as **Confirmed true positive**, **False positive** (explain why, in one line), or **Needs human judgement** (e.g. exploitability depends on deployment context you can't see from the code alone)

Only "Confirmed true positive" and "Needs human judgement" findings go in the final report to the user. Silently dropping false positives without explanation is fine for the summary, but keep your reasoning available if the user asks why a raw PySpector finding didn't make the cut.

Do not attempt to actually exploit anything (no live PoC execution, no reaching out to external services, no running injected payloads). This is a static re-read and reasoning pass only, not a penetration test.

## Step 7: Report

Default to HTML when the deliverable is for the user to read, PySpector's own HTML report is fine to hand over directly, or you can write your own summary. Use JSON instead only if the user says the output needs to be consumed by another tool or script.

Your own summary to the user (in addition to, or instead of, PySpector's raw report) should include:

- What was scanned, and which flags were used and why (tie back to what recon found, e.g. "used the AI ruleset because the project imports `openai` and `langchain`")
- Total raw findings vs. verified true positives, so the user sees the verification happened
- Each confirmed true positive: file, line, vulnerability class, why it's exploitable (the taint path), and severity
- Anything flagged "needs human judgement" and why
- Supply-chain CVEs, if that check was used: package, installed version, CVE ID, and whether a fixed version is available

If findings exist, offer to help fix them as a natural next step, but that's a separate task from the audit itself; don't start patching without the user asking.

## Notes / gotchas

- Always trust the live `pyspector --help` / `pyspector scan --help` output over anything written in this document
- If the Rust toolchain install requires a shell restart or sourcing `~/.cargo/env`, do that before retrying `pyspector` commands in the same session
- A `.pyspector_baseline.json` in the repo root from a prior human triage session will suppress previously-dismissed findings automatically. Mention this to the user if the finding count looks lower than expected
- `pyspector watch` and `pyspector triage` are interactive tools for the user to run themselves, never invoke them on the user's behalf
- Remote scanning via `--url` only works for public GitHub/GitLab repos; for private repos, work from a local copy instead
- The first scan of a given codebase builds an AST cache and will be slower than subsequent scans of the same codebase, even after minor source changes
