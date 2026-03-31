import json
import html as html_module
from sarif_om import (
    SarifLog,
    Tool,
    ToolComponent,
    Run,
    ReportingDescriptor,
    MultiformatMessageString,
    Result,
    ArtifactLocation,
    Location,
    PhysicalLocation,
    Region,
    Message,
)

# Maps internal severity levels to SARIF-compliant level strings.
_SEVERITY_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
}

_PYSPECTOR_VERSION = "1.0.0"

def _clean(obj):
    """
    Recursively serialize a sarif_om object to a plain dict,
    dropping any key whose value is None so the output stays lean.
    sarif_om objects expose their data via __dict__; we walk that
    structure and strip falsy-None leaves.
    """
    if isinstance(obj, list):
        return [_clean(item) for item in obj]
    if hasattr(obj, "__dict__"):
        return {
            k: _clean(v)
            for k, v in obj.__dict__.items()
            if v is not None
        }
    return obj


class Reporter:
    def __init__(self, issues: list, report_format: str):
        self.issues = issues
        self.format = report_format

    def generate(self) -> str:
        if self.format == "json":
            return self.to_json()
        if self.format == "sarif":
            return self.to_sarif()
        if self.format == "html":
            return self.to_html()
        return self.to_console()

    # ------------------------------------------------------------------ #
    #  Console                                                             #
    # ------------------------------------------------------------------ #

    def to_console(self) -> str:
        if not self.issues:
            return "\nNo issues found."

        output = []
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

        issues_by_severity: dict[str, list] = {}
        for issue in self.issues:
            severity = str(issue.severity).split(".")[-1].upper()
            issues_by_severity.setdefault(severity, []).append(issue)

        for severity in severity_order:
            if severity not in issues_by_severity:
                continue

            sorted_issues = sorted(
                issues_by_severity[severity],
                key=lambda i: (i.file_path, i.line_number),
            )
            output.append(f"\n{'='*60}")
            output.append(
                f"  {severity} ({len(sorted_issues)} issue{'s' if len(sorted_issues) != 1 else ''})"
            )
            output.append(f"{'='*60}")

            for issue in sorted_issues:
                output.append(
                    f"\n[+] Rule ID: {issue.rule_id}\n"
                    f"    Description: {issue.description}\n"
                    f"    File: {issue.file_path}:{issue.line_number}\n"
                    f"    Code: `{issue.code.strip()}`"
                )

        return "\n".join(output)

    # ------------------------------------------------------------------ #
    #  JSON                                                                #
    # ------------------------------------------------------------------ #

    def to_json(self) -> str:
        report = {
            "summary": {"issue_count": len(self.issues)},
            "issues": [
                {
                    "rule_id": issue.rule_id,
                    "description": issue.description,
                    "file_path": issue.file_path,
                    "line_number": issue.line_number,
                    "code": issue.code,
                    "severity": str(issue.severity).split(".")[-1],
                    "remediation": issue.remediation,
                }
                for issue in self.issues
            ],
        }
        return json.dumps(report, indent=2)

    # ------------------------------------------------------------------ #
    #  SARIF                                                               #
    # ------------------------------------------------------------------ #

    def to_sarif(self) -> str:
        """
        Produces a SARIF 2.1.0 document.

        Improvements over the previous implementation:
        - Uses ToolComponent (correct type for Tool.driver).
        - Builds a deduplicated, ordered rule list and references rules by
          index in each Result (rule_index), which is required for tooling
          that doesn't index rules by ID alone.
        - Maps internal severity levels to the SARIF `level` field
          (error / warning / note) so consumers can filter by severity
          without understanding PySpector-specific values.
        - Surfaces remediation guidance in rule.help so it appears in
          IDEs and dashboards that consume SARIF.
        - Uses proper Message / MultiformatMessageString objects instead
          of raw dicts.
        - Serialises via a custom _clean() helper that drops None-valued
          keys, keeping the output compact and spec-compliant.
        """

        # ── 1. Build an ordered, deduplicated rule list ──────────────────
        rule_index_map: dict[str, int] = {}
        rules: list[ReportingDescriptor] = []

        for issue in self.issues:
            if issue.rule_id in rule_index_map:
                continue

            severity_key = str(issue.severity).split(".")[-1].upper()

            rule = ReportingDescriptor(
                id=issue.rule_id,
                name=issue.rule_id,  # human-friendly CamelCase id is conventional
                short_description=MultiformatMessageString(
                    text=issue.description
                ),
                # help surfaces remediation in GitHub Advanced Security, VS Code, etc.
                help=MultiformatMessageString(
                    text=issue.remediation or issue.description,
                    markdown=(
                        f"**Remediation:** {issue.remediation}"
                        if issue.remediation
                        else None
                    ),
                ),
                # default_configuration carries the base severity level for the rule
                default_configuration={"level": _SEVERITY_TO_SARIF_LEVEL.get(severity_key, "warning")},
            )

            rule_index_map[issue.rule_id] = len(rules)
            rules.append(rule)

        # ── 2. Assemble the Tool ─────────────────────────────────────────
        driver = ToolComponent(
            name="PySpector",
            version=_PYSPECTOR_VERSION,
            information_uri="https://github.com/your-org/pyspector",
            rules=rules,
        )
        tool = Tool(driver=driver)

        # ── 3. Build Results ─────────────────────────────────────────────
        results: list[Result] = []

        for issue in self.issues:
            severity_key = str(issue.severity).split(".")[-1].upper()
            level = _SEVERITY_TO_SARIF_LEVEL.get(severity_key, "warning")

            region = Region(
                start_line=issue.line_number,
                # Snippet lets viewers show the offending code inline
                snippet=MultiformatMessageString(text=issue.code.strip()),
            )

            location = Location(
                physical_location=PhysicalLocation(
                    artifact_location=ArtifactLocation(
                        uri=issue.file_path,
                        # uri_base_id makes paths relative to the repo root,
                        uri_base_id="%SRCROOT%",
                    ),
                    region=region,
                )
            )

            result = Result(
                rule_id=issue.rule_id,
                rule_index=rule_index_map[issue.rule_id],
                level=level,
                message=Message(text=issue.description),
                locations=[location],
            )

            results.append(result)

        # ── 4. Compose the log ───────────────────────────────────────────
        run = Run(tool=tool, results=results)
        log = SarifLog(
            version="2.1.0",
            schema_uri=(
                "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                "master/Schemata/sarif-schema-2.1.0.json"
            ),
            runs=[run],
        )

        # ── 5. Serialise, stripping None values ──────────────────────────
        return json.dumps(_clean(log), indent=2)

    def to_html(self) -> str:
        html = f"""
        <html>
        <head><title>PySpector Scan Report</title></head>
        <body>
        <h1>PySpector Scan Report</h1>
        <h2>Found {len(self.issues)} issues.</h2>
        <table border='1' style='border-collapse: collapse; width: 100%;'>
        <tr style='background-color: #f2f2f2;'>
            <th style='padding: 8px; text-align: left;'>File</th>
            <th style='padding: 8px; text-align: left;'>Line</th>
            <th style='padding: 8px; text-align: left;'>Severity</th>
            <th style='padding: 8px; text-align: left;'>Description</th>
            <th style='padding: 8px; text-align: left;'>Code</th>
        </tr>
        """
        for issue in self.issues:
            html += f"""
            <tr>
                <td style='padding: 8px;'>{html_module.escape(issue.file_path)}</td>
                <td style='padding: 8px;'>{issue.line_number}</td>
                <td style='padding: 8px;'>{html_module.escape(str(issue.severity))}</td>
                <td style='padding: 8px;'>{html_module.escape(issue.description)}</td>
                <td style='padding: 8px;'><pre><code>{html_module.escape(issue.code)}</code></pre></td>
            </tr>
            """
        html += "</table></body></html>"
        return html
