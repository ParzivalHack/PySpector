# Security Policy — PySpector Vulnerability Disclosure Program (VDP)

Thank you for helping to keep **PySpector** secure.  
We encourage responsible disclosure of all security vulnerabilities in our codebase.

---

## 🧭 How to Report
All security issues must be reported **privately** through our official form:  
👉 [**PySpector Vulnerability Disclosure Form**](https://xobusaqs.forms.app/pyspector-vdp-form)

This form collects all details we need for efficient triage, including:
1. **Full Name (for credits)** — You may remain anonymous by writing “N/A”.
2. **Preferred Email Address** — Used only for coordinated disclosure or clarification.
3. **Vulnerability Title** — e.g., `OS Command Injection in cli.py leading to arbitrary command execution`.
4. **Affected Version(s)** — e.g., `v0.1.3-beta`.
5. **Severity (CVSS 4.0)** — Choose between *Low, Medium, High, Critical*.
6. **Vulnerability Description** — Include CWE (if applicable), vector, and clear explanation.
7. **Impact Explanation** — Describe the potential effect on PySpector or its users.
8. **Steps to Reproduce** — Provide detailed reproduction instructions.
9. **Proof of Concept (PoC)** — Upload a *safe, minimal PoC* (`.txt` file) written in **Python**, **Bash/Shell**, **Rust**, **PowerShell**, or **Batchfile**.

We aim to **acknowledge within 48 hours** and provide a **status update within 7 days**.

---

## 🧩 In-Scope Vulnerabilities
We consider valid reports for:
- Remote or local code execution within PySpector or its components (Python CLI, Rust backend).
- Privilege escalation or sandbox escape via plugins.
- Bypass of PySpector’s static analysis, rule execution, or scanning logic.
- Sensitive information exposure (e.g., reading system paths, credentials, or code fragments unexpectedly).
- Supply-chain or packaging flaws (e.g., tampered distributions, missing signatures/checksums).
- Insecure default configurations that expose users to risks when used as documented.

---

## 🚫 Out-of-Scope
The following are **not eligible** under this program:
- Security issues in third-party dependencies unless exploitable *through* PySpector.
- Findings in code analyzed *by* PySpector (i.e., the user’s code).
- Feature requests, UX improvements, or non-security bugs.
- Denial-of-Service (DoS) attacks requiring unrealistic resource usage.
- Vulnerabilities requiring root/admin privileges or access to developer secrets.
- Attacks on PySpector’s infrastructure (e.g., GitHub Actions, website, form hosting).

---

## 🕒 Disclosure & Fix Timeline
We follow a **responsible disclosure process**:

1. **Private Triage** — Report received, validated, and acknowledged.
2. **Coordination** — Fix is developed in a private branch; the reporter may be invited to verify the patch.
3. **Release** — A patched version is published on PyPI and GitHub.
4. **Advisory Publication** — A GitHub Security Advisory (GHSA) is released with technical details and credit.
5. **Credit** — Reporter is listed under acknowledgements unless anonymity was requested.

---

## 🏅 Recognition & Credit Policy
We do not currently offer monetary rewards.  
However:
- Valid reporters will be **publicly credited** in the advisory and release notes.
- Anonymous submissions (using “N/A”) will be processed equally and respected.
- Duplicate or low-impact findings may receive private acknowledgement only.

---

## 🛡️ Safe-Harbor Statement
We support **good-faith security research**.  
You will **not face legal action** if:
- You report the vulnerability promptly via the official form.
- You avoid accessing, modifying, or exfiltrating user data.
- You do not exploit or publicly disclose the issue before a fix is released.
- Your testing remains within the scope of PySpector’s open-source codebase.

Violations involving data exfiltration, destructive testing, or public disclosure prior to coordination, void this protection.

---

## 💬 Contact
Questions or clarifications?  
You can [Contact](mailto:pyspector@protonmail. com) maintainers directly.

All reports and communications will be handled confidentially.

---

Thank you for helping improve the security and reliability of **PySpector**.  
— *The PySpector Team*