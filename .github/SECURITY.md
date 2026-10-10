## Security Policy: PySpector Vulnerability Disclosure Program (VDP)

Thank you for helping to keep **PySpector** secure.  
We encourage responsible disclosure of all security vulnerabilities in our codebase.

## 👉 How to Report

All security issues must be reported **privately** through **GitHub Security Advisories**:  
[**Report a Vulnerability here**](https://github.com/ParzivalHack/PySpector/security/advisories/new)

This is our preferred channel because it keeps the disclosure private until a fix is released, allows for direct collaboration between you and the maintainers, and enables us to **formally request a CVE on your behalf**.

Before submitting, please read the [Threat Model](#-threat-model), the [In-Scope](#-in-scope-vulnerabilities) and [Out-of-Scope](#-out-of-scope) sections, and the [Report Requirements](#-report-requirements--spam-policy) below.

When submitting, please include:
1. **Title:** A concise, descriptive title like "OS Command Injection in cli.py leading to arbitrary command execution".
2. **Description:** An ideal report must have the following:
   - Vulnerability Summary and Description: What kind of vulnerability is it? What is the flaw that causes it?
   - Impact: What is the impact on users or systems, and who is affected by this vulnerability?
   - PoC: Please attach a PoC script (preferably in Python, Bash or Rust) demonstrating the vulnerability in a non-simulated way, against a supported component and the latest release.
   - References: Any relevant links (CVEs, write-ups, similar issues, related code).
3. **Affected products**: Always set "Ecosystem" to **pip** and "Package name" to **pyspector**, regardless of whether the vulnerability is in the Python CLI or the Rust core. Fill in the affected version range (e.g. <= 0.1.6) and patched version (if any).
4. **Severity**: Assess using **CVSS v4.0** and generate the full vector string (e.g. CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N), using the built-in calculator.
5. **Weaknesses (CWE)**: Search and select the most applicable CWE identifier(s) for the vulnerability type.
6. **Credits**: Add your GitHub username, full name, or email address so we can credit you in the published advisory. You may leave this blank to remain anonymous.

We aim to **acknowledge within 48 hours** and provide a **status update within 7 days**.

> **Alternatively**, if you are unable to use GitHub Advisories, you may contact the maintainers directly at [pyspector@protonmail.com](mailto:pyspector@protonmail.com). However, GitHub Advisories is the **strongly preferred channel**, and if you submit via email, you may receive a delayed response.

## 📋 Report Requirements & Spam Policy

To keep triage fast and fair for everyone, every report must meet the following requirements:

1. **One vulnerability per advisory.** If you found several issues, submit each one separately.
2. **Reproducible on the latest release** published on PyPI, against a **supported component**, with a working, non-simulated PoC.
3. **A CVSS v4.0 vector string and a CWE** selected by you. A report without a valid severity is considered incomplete.
4. **Verified by a human.** AI-assisted reports are welcome only if you have personally reproduced and validated every claim in them. You are responsible for the accuracy of what you submit.
5. **Consistent with this policy.** Your report must respect the [Threat Model](#-threat-model) and must not target anything listed under [Out-of-Scope](#-out-of-scope).

Reports that bundle multiple issues, omit a valid severity, target out-of-scope components, ignore the threat model, or contain unverified AI-generated content **will be closed as Spam without a detailed response**, and are not eligible for credit, a CVE request, or Hall of Fame listing.

## 🏅 Recognition, CVEs & Incentives

We believe valid security research **deserves meaningful recognition**. For every **valid, in-scope** vulnerability report:

- **CVE Assignment**: We will formally request a **CVE ID** on your behalf through **GitHub's CNA partnership**, giving your finding a **permanent, citable record** in the public vulnerability database.
- **Public Credit**: You will be named in the GitHub Security Advisory and in the release notes (unless you request anonymity).
- **Hall of Fame**: Reporters of Medium severity (or higher) findings will be listed in a dedicated Security HoF section in the repository.

Anonymous submissions (using "N/A") **are processed equally and respected**, though CVE credit will be listed as "Anonymous Researcher" unless you provide a name.

Duplicate or low-impact findings may receive private acknowledgement only, and may **not be eligible** for CVE requests.

## 🎯 Threat Model

PySpector is a **local command-line tool**. It is run by a developer, on their own machine or CI runner, against code they choose.

- **The person running the CLI is trusted**, including every argument, flag, and configuration file they provide (for example `--url`, `-o`, etc...).
- **The content of the scanned target is untrusted**: source files, file names, repository contents, and any configuration or rule files bundled inside it.
- A valid vulnerability is one where **untrusted data crosses that boundary** and lets an attacker affect the machine running PySpector.
- The `--url` option only accepts `github.com` and `gitlab.com` repositories.

A report that requires the victim to type an attacker-chosen payload into their own terminal does not cross this boundary, because the attacker and the victim are the same person.

## 🧩 In-Scope Vulnerabilities

We consider valid reports for security-relevant flaws in supported components that meaningfully affect PySpector users or underlying systems, and that fit the threat model above. Below are the categories we generally consider in-scope, with relevant CWEs as guidance:

**Code & Command Execution**
- **Command Injection (CWE-77/78)**: untrusted content inside a scanned target (file names, repository contents, configuration or rule files bundled with it) reaching `subprocess` calls and executing attacker-controlled commands on the machine running PySpector.
- **Arbitrary Code Execution via Malicious Input (CWE-94)**: crafting a `.toml` ruleset or scan target that causes PySpector to execute attacker-controlled code during a scan.

**Path & File System**
- **Path Traversal and Arbitrary File Write (CWE-22/73)**: crafted content in a scanned target (symlinks, malicious paths inside a repository or archive) causing PySpector to read or write files outside the intended scope.

**Memory Safety (Rust Core)**
- **Memory corruption, buffer overflows, or use-after-free (CWE-119/416)**: especially when the Rust engine parses attacker-controlled Python AST JSON or TOML rule files.
- **Integer overflow in analysis logic (CWE-190)**: leading to incorrect behavior or exploitable conditions in the Rust core.

**Supply Chain & Distribution**
- **Tampered PyPI package or missing integrity checks (CWE-494)**: for example, the published package lacking checksums or being susceptible to substitution attacks.
- **Dependency confusion or typosquatting in `requirements.txt` / `Cargo.toml` (CWE-829)**: exploitable through PySpector's own dependency tree.

**Information Disclosure**
- **Unintended exposure of credentials or system paths through error messages or logs (CWE-200/532)**: for example, verbose error reporting leaking data beyond what the user requested. Reporting flagged code lines, including detected hardcoded secrets, to the user who ran the scan is intended behavior and is not a vulnerability.

## 🚫 Out-of-Scope

The following are **not eligible** under this program:
- **The legacy REST API server** (the `/scan` HTTP endpoint). It is an unsupported development and testing component, it is not a production deployment, and it is scheduled for removal from the repository. Issues in it, including SSRF, missing authentication, path handling, and information disclosure, are out of scope.
- **Arguments supplied by the local user** on their own command line (`--url`, `-o`, and so on). The person running the CLI is trusted, and reports that require a victim to enter an attacker-chosen payload into their own terminal are out of scope.
- **Behavior of `git` itself**, or issues that only appear on outdated or unsupported versions of git, Python, or the operating system.
- **Intended output**: the display of flagged source lines, including detected secrets, in scan reports. Showing the user what was found is the purpose of a SAST tool.
- **Non-product code**: anything in `tests/`, `benchmarks/`, examples, unreleased branches, or anything not shipped in the latest PyPI release.
- **Hardening suggestions** and missing best practices without a demonstrable security impact on a supported component.
- Security issues in third-party dependencies unless directly exploitable *through* PySpector.
- Findings in code analyzed *by* PySpector (i.e., vulnerabilities in the user's own scanned codebase).
- False negatives or false positives in PySpector's detection rules: these are quality issues, not security vulnerabilities (you are invited to open an issue though).
- Feature requests, UX improvements, or non-security bugs.
- Denial-of-Service attacks requiring unrealistic resource usage or physical access.
- Vulnerabilities requiring root/admin privileges or prior access to developer secrets.
- Attacks on PySpector's infrastructure (for example GitHub Actions, PyPI account, domain).
- PySpector's plugin system was removed entirely in v0.2.1 due to hard-to-patch classes of vulnerabilities and low community use of the feature. It no longer exists in the codebase and is therefore out of scope.

## 🕒 Disclosure & Fix Timeline

We follow a **responsible disclosure process**:

1. **Private Triage**: Report received via GitHub Advisory, checked against this policy, validated, and acknowledged.
2. **Coordination**: Fix is developed in a private branch; the reporter may be invited to verify the patch.
3. **Release**: A patched version is published on PyPI and GitHub.
4. **CVE Request**: A CVE is formally requested through **GitHub's CNA on the reporter's behalf**.
5. **Advisory Publication**: The GitHub Security Advisory is published with technical details and **full credits**.
6. **Credit**: Reporter is listed under acknowledgements unless anonymity was requested.

## 🛡️ Safe-Harbor Statement

We support **good-faith security research**.  
You will **not face any legal action** if:
- You always act ethically and in good faith.
- You report the vulnerability promptly via GitHub Security Advisories or our contact email.
- You avoid accessing, modifying, or exfiltrating user data.
- You do not exploit or publicly disclose the issue before a fix is released.
- Your testing remains within the scope of PySpector's open-source codebase.

Violations involving data exfiltration, destructive testing, or public disclosure prior to coordination *void this protection*.

## 💬 Contact

Questions or clarifications?  
You can [contact](mailto:pyspector@protonmail.com) maintainers directly.

All reports and communications will be handled confidentially.

Thank you for helping improve the security and reliability of **PySpector**.  
— *The PySpector Team*
