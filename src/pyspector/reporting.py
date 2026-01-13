import json
# Added 'Region' to imports for better SARIF compliance
from sarif_om import SarifLog, Tool, Run, ReportingDescriptor, Result, ArtifactLocation, Location, PhysicalLocation, Region
# Removed 'asdict' from imports as it is not needed for sarif_om
from dataclasses import asdict, is_dataclass

class Reporter:
    def __init__(self, issues: list, report_format: str):
        self.issues = issues
        self.format = report_format

    def generate(self) -> str:
        if self.format == 'json':
            return self.to_json()
        if self.format == 'sarif':
            return self.to_sarif()
        if self.format == 'html':
            return self.to_html()
        return self.to_console()

    def to_console(self) -> str:
        if not self.issues:
            return "\nNo issues found."

        output = []

        # Define severity order (highest to lowest priority)
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

        # Group issues by severity
        issues_by_severity = {}
        for issue in self.issues:
            severity = str(issue.severity).split('.')[-1].upper()
            if severity not in issues_by_severity:
                issues_by_severity[severity] = []
            issues_by_severity[severity].append(issue)

        # Output grouped by severity (in priority order)
        for severity in severity_order:
            if severity not in issues_by_severity:
                continue

            issues = issues_by_severity[severity]
            # Sort issues within each severity group by file path and line number
            sorted_issues = sorted(issues, key=lambda i: (i.file_path, i.line_number))

            # Add severity header
            output.append(f"\n{'='*60}")
            output.append(f"  {severity} ({len(sorted_issues)} issue{'s' if len(sorted_issues) != 1 else ''})")
            output.append(f"{'='*60}")

            for issue in sorted_issues:
                output.append(
                    f"\n[+] Rule ID: {issue.rule_id}\n"
                    f"    Description: {issue.description}\n"
                    f"    File: {issue.file_path}:{issue.line_number}\n"
                    f"    Code: `{issue.code.strip()}`"
                )

        return "\n".join(output)

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
                    "severity": str(issue.severity).split('.')[-1],
                    "remediation": issue.remediation,
                } for issue in self.issues
            ]
        }
        return json.dumps(report, indent=2)

    def to_sarif(self) -> str:
        tool = Tool(driver=ReportingDescriptor(id="pyspector", name="PySpector"))
        rules = []
        results = []
        
        # Create a unique list of rules for the SARIF report
        rule_map = {}
        for issue in self.issues:
            if issue.rule_id not in rule_map:
                rule_map[issue.rule_id] = ReportingDescriptor(id=issue.rule_id, name=issue.description)
        
        # sarif_om expects lists, not values view
        tool.driver.rules = list(rule_map.values())

        for issue in self.issues:
            # FIX: Use the Region object from sarif_om instead of a raw dict
            region = Region(start_line=issue.line_number)
            
            location = Location(
                physical_location=PhysicalLocation(
                    artifact_location=ArtifactLocation(uri=issue.file_path),
                    region=region
                )
            )
            results.append(Result(rule_id=issue.rule_id, message={"text": issue.description}, locations=[location]))
        
        run = Run(tool=tool, results=results)
        log = SarifLog(version="2.1.0", schema_uri="https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json", runs=[run])
        
        # FIX: Remove asdict(). Use default lambda to serialize non-dataclass objects.
        return json.dumps(log, default=lambda o: o.__dict__, indent=2)
        
    def to_html(self) -> str:
        # A simple HTML report
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
                <td style='padding: 8px;'>{issue.file_path}</td>
                <td style='padding: 8px;'>{issue.line_number}</td>
                <td style='padding: 8px;'>{str(issue.severity)}</td>
                <td style='padding: 8px;'>{issue.description}</td>
                <td style='padding: 8px;'><pre><code>{issue.code}</code></pre></td>
            </tr>
            """
        html += "</table></body></html>"
        return html