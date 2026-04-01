import json
import html as html_module
import importlib.metadata

from sarif_om import (
    SarifLog,
    Tool,
    ToolComponent,
    Run,
    ReportingDescriptor,
    ReportingConfiguration,
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
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def _get_version():
    """Return installed PySpector version dynamically."""
    try:
        return importlib.metadata.version("pyspector")
    except importlib.metadata.PackageNotFoundError:
        return "dev"


_PYSPECTOR_VERSION = _get_version()


def _severity_key(issue) -> str:
    """Normalize enum-like severity values."""
    return str(issue.severity).split(".")[-1].upper()


def _clean(obj):

    if isinstance(obj, list):
        return [_clean(item) for item in obj]

    if isinstance(obj, dict):
        return {
            k: _clean(v)
            for k, v in obj.items()
            if v is not None
        }

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


    def to_console(self) -> str:
        if not self.issues:
            return "\nNo issues found."

        output = []
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

        issues_by_severity: dict[str, list] = {}
        for issue in self.issues:
            severity = _severity_key(issue)
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
    #  JSON                                                              #
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
                    "severity": _severity_key(issue),
                    "remediation": issue.remediation,
                }
                for issue in self.issues
            ],
        }

        return json.dumps(report, indent=2)

    # ------------------------------------------------------------------ #
    #  SARIF                                                             #
    # ------------------------------------------------------------------ #

    def to_sarif(self) -> str:

        rule_index_map: dict[str, int] = {}
        rules: list[ReportingDescriptor] = []

        for issue in self.issues:

            if issue.rule_id in rule_index_map:
                continue

            severity_key = _severity_key(issue)

            rule = ReportingDescriptor(
                id=issue.rule_id,
                name=issue.rule_id,
                short_description=MultiformatMessageString(
                    text=issue.description
                ),
                help=MultiformatMessageString(
                    text=issue.remediation or issue.description,
                    markdown=(
                        f"**Remediation:** {issue.remediation}"
                        if issue.remediation
                        else None
                    ),
                ),
                default_configuration=ReportingConfiguration(
                    level=_SEVERITY_TO_SARIF_LEVEL.get(
                        severity_key,
                        "warning",
                    )
                ),
            )

            rule_index_map[issue.rule_id] = len(rules)
            rules.append(rule)

        driver = ToolComponent(
            name="PySpector",
            version=_PYSPECTOR_VERSION,
            information_uri="https://github.com/your-org/pyspector",
            rules=rules,
        )

        tool = Tool(driver=driver)

        results: list[Result] = []

        for issue in self.issues:

            severity_key = _severity_key(issue)
            level = _SEVERITY_TO_SARIF_LEVEL.get(
                severity_key,
                "warning",
            )

            region = Region(
                start_line=issue.line_number,
                snippet=MultiformatMessageString(
                    text=issue.code.strip()
                ),
            )

            location = Location(
                physical_location=PhysicalLocation(
                    artifact_location=ArtifactLocation(
                        uri=issue.file_path,
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

        run = Run(tool=tool, results=results)

        log = SarifLog(
            version="2.1.0",
            schema_uri=(
                "https://raw.githubusercontent.com/oasis-tcs/"
                "sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
            ),
            runs=[run],
        )

        return json.dumps(_clean(log), indent=2)

    # ------------------------------------------------------------------ #
    #  HTML                                                              #
    # ------------------------------------------------------------------ #

    def to_html(self) -> str:
        html = f"""
        <html>
        <head><title>PySpector Scan Report</title></head>
        <body>
        <h1>PySpector Scan Report</h1>
        <h2>Found {len(self.issues)} issues.</h2>
        <table border='1' style='border-collapse: collapse; width: 100%;'>
        <tr style='background-color: #f2f2f2;'>
            <th style='padding: 8px;'>File</th>
            <th style='padding: 8px;'>Line</th>
            <th style='padding: 8px;'>Severity</th>
            <th style='padding: 8px;'>Description</th>
            <th style='padding: 8px;'>Code</th>
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
