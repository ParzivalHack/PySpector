## Security Policy: PySpector Vulnerability Disclosure Program (VDP)

Thank you for helping to keep **PySpector** secure.  
We encourage responsible disclosure of all security vulnerabilities in our codebase.

## 👉 How to Report

All security issues must be reported **privately** through **GitHub Security Advisories**:  
[**Report a Vulnerability here**](https://github.com/ParzivalHack/PySpector/security/advisories/new)

This is our preferred channel because it keeps the disclosure private until a fix is released, allows for direct collaboration between you and the maintainers, and enables us to **formally request a CVE on your behalf**.

When submitting, please include:
1. **Title:** A concise, descriptive title like "OS Command Injection in cli.py leading to arbitrary command execution".
2. **Description:** An ideal report, must have the following:
- Vulnerability Summary and Description: What kind of vulnerability is it? What's the flaw that causes it?
- Impact: What's the impact on users or systems and who is affected by this vulnerability?
- PoC: Can you attach a PoC script (preferably in Python, Bash or Rust) demostrating the vulnerability in a non-simulated way?
- References: Any relevant links (CVEs, write-ups, similar issues, related code)?
3. **Affected products**: Always set "Ecosystem" to **pip** and "Package name" to **pyspector**, regardless of whether the vulnerability is in the Python CLI or the Rust core. Fill in the affected version range (i.e. <= 0.1.6) and patched version (if any).
4. **Severity**: Assess using **CVSS v3.1** and generate the full vector string (i.e. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H), using the built-in calculator.
5. **Weaknesses (CWE)**: Search and select the most applicable CWE identifier(s) for the vulnerability type.
6. **Credits**: Add your GitHub username, full name, or email address so we can credit you in the published advisory. You may leave this blank to remain anonymous.

We aim to **acknowledge within 48 hours** and provide a **status update within 7 days**.

> **Alternatively**, if you are unable to use GitHub Advisories, you may contact the maintainers directly at [pyspector@protonmail.com](mailto:pyspector@protonmail.com). However, GitHub Advisories is the **strongly preferred channel**, and if you submit via email, you may receive a delayed response.

## 🏅 Recognition, CVEs & Incentives

We believe valid security research **deserves meaningful recognition**. For every **valid, in-scope** vulnerability report:

- **CVE Assignment**: We will formally request a **CVE ID** on your behalf through **GitHub's CNA partnership**, giving your finding a **permanent, citable record** in the public vulnerability database.
- **Public Credit**: You will be named in the GitHub Security Advisory and in the release notes (unless you request anonymity).
- **Hall of Fame**: Reporters of High or Critical severity findings will be listed in a dedicated Security HoF section in the repository.

Anonymous submissions (using "N/A") **are processed equally and respected**, though CVE credit will be listed as "Anonymous Researcher" unless you provide a name.

Duplicate or low-impact findings may receive private acknowledgement only, and **will not be eligible** for CVE requests.

## 🧩 In-Scope Vulnerabilities

We consider valid reports for any security-relevant flaw that meaningfully affects PySpector users or underlying systems. Below are the categories we generally consider in-scope, with relevant CWEs as guidance, including (but not limited to):

**Code & Command Execution**
- **Command Injection (CWE-77/78)**: like, unsanitized user input reaching `subprocess` calls in the CLI or Rust API, such as through the `--url` git clone functionality.
- **Arbitrary Code Execution via Malicious Input (CWE-94)**: crafting a `.toml` ruleset, plugin, or scan target that causes PySpector to execute attacker-controlled code during a scan.
- **Plugin Sandbox Escape (CWE-693)**: bypassing the plugin trust model, checksum verification, or AST-based static inspection to load and execute untrusted code.
**Path & File System**
- **Path Traversal (CWE-22)**: manipulating scan paths, output file paths, or plugin file resolution to read or write files outside the intended scope.
- **Arbitrary File Write via Output Parameters (CWE-73)**: like, the REST API or CLI writing scan output to an attacker-controlled location on disk.
**Network & API**
- **Server-Side Request Forgery (CWE-918)**: abusing the REST API `/scan` endpoint's `url` parameter to make the server issue requests to internal or otherwise unreachable hosts.
- **Authentication or Authorization Bypass (CWE-306/862)**: accessing or manipulating scan functionality on the REST API without proper authorization.
**Memory Safety (Rust Core)**
- **Memory corruption, buffer overflows, or use-after-free (CWE-119/416)**: especially when the Rust engine parses attacker-controlled Python AST JSON or TOML rule files.
- **Integer overflow in analysis logic (CWE-190)**: leading to incorrect behavior or exploitable conditions in the Rust core.
**Supply Chain & Distribution**
- **Tampered PyPI package or missing integrity checks (CWE-494)**: like, the published package lacking checksums or being susceptible to substitution attacks.
- **Dependency confusion or typosquatting in `requirements.txt` / `Cargo.toml` (CWE-829)**: exploitable through PySpector's own dependency tree.
**Information Disclosure**
- **Unintended exposure of scanned file contents, credentials, or system paths through output or error messages (CWE-200/532)**: like, verbose error reporting leaking data beyond what the user intended to expose.

## 🚫 Out-of-Scope

The following are **not eligible** under this program:
- Security issues in third-party dependencies unless directly exploitable *through* PySpector.
- Findings in code analyzed *by* PySpector (i.e., vulnerabilities in the user's own scanned codebase).
- False negatives or false positives in PySpector's detection rules: these are quality issues, not security vulnerabilities (you are invited to open an issue though).
- Feature requests, UX improvements, or non-security bugs.
- Denial-of-Service attacks requiring unrealistic resource usage or physical access.
- Vulnerabilities requiring root/admin privileges or prior access to developer secrets.
- Attacks on PySpector's infrastructure (like, GitHub Actions, PyPI account, domain).

## 🕒 Disclosure & Fix Timeline

We follow a **responsible disclosure process**:

1. **Private Triage**: Report received via GitHub Advisory, validated, and acknowledged.
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
