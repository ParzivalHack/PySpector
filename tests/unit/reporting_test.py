import json
import re
import unittest
from enum import Enum
from html.parser import HTMLParser
from types import SimpleNamespace

from pyspector.reporting import Reporter


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


def make_issue(
    *,
    rule_id="PY001",
    cwe="CWE-95",
    description="Use of eval() is highly dangerous.",
    file_path="path/to/file.py",
    line_number=1,
    code='eval("a=5")',
    severity=Severity.HIGH,
    remediation="Avoid eval(). Use safer alternatives like ast.literal_eval.",
):
    return SimpleNamespace(
        rule_id=rule_id,
        cwe=cwe,
        description=description,
        file_path=file_path,
        line_number=line_number,
        code=code,
        severity=severity,
        remediation=remediation,
    )


class ReportHtmlParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self._tag_stack = []
        self.title = ""
        self.h1 = []
        self.h2 = []
        self.headers = []
        self.rows = []
        self._current_row = None
        self._current_cell = None

    def handle_starttag(self, tag, attrs):
        self._tag_stack.append(tag)
        if tag == "tr":
            self._current_row = []
        elif tag in {"td", "th"}:
            self._current_cell = []

    def handle_data(self, data):
        if not self._tag_stack:
            return

        tag = self._tag_stack[-1]
        if tag == "title":
            self.title += data
        elif tag == "h1":
            self.h1.append(data)
        elif tag == "h2":
            self.h2.append(data)
        elif self._current_cell is not None:
            self._current_cell.append(data)

    def handle_endtag(self, tag):
        if tag == "td" and self._current_row is not None:
            self._current_row.append("".join(self._current_cell).strip())
            self._current_cell = None
        elif tag == "th":
            self.headers.append("".join(self._current_cell).strip())
            self._current_cell = None
        elif tag == "tr" and self._current_row:
            self.rows.append(self._current_row)
            self._current_row = None

        if self._tag_stack and self._tag_stack[-1] == tag:
            self._tag_stack.pop()


class TestReporter(unittest.TestCase):
    def test_to_json_includes_summary_and_issue_fields(self):
        issue = make_issue()

        output = Reporter([issue], "json").to_json()
        report = json.loads(output)

        self.assertEqual(report["summary"]["issue_count"], 1)
        self.assertEqual(
            report["issues"][0],
            {
                "rule_id": issue.rule_id,
                "cwe": issue.cwe,
                "description": issue.description,
                "file_path": issue.file_path,
                "line_number": issue.line_number,
                "code": issue.code,
                "severity": "HIGH",
                "remediation": issue.remediation,
            },
        )

    def test_to_sarif_builds_valid_run_rules_and_results(self):
        issues = [
            make_issue(
                rule_id="PY001",
                cwe="CWE-95",
                severity=Severity.HIGH,
                file_path="src/a.py",
                line_number=7,
                code="eval(user_input)",
            ),
            make_issue(
                rule_id="PY001",
                cwe="CWE-95",
                severity=Severity.MEDIUM,
                file_path="src/b.py",
                line_number=3,
                code="exec(template)",
            ),
            make_issue(
                rule_id="PY999",
                cwe=None,
                severity="Informational",
                file_path="src/c.py",
                line_number=12,
                code="print(value)",
            ),
            make_issue(
                rule_id="PY010",
                cwe="CWE-20",
                severity=Severity.LOW,
                file_path="src/d.py",
                line_number=21,
                code="input()",
            ),
        ]

        output = Reporter(issues, "sarif").to_sarif()
        report = json.loads(output)

        self.assertEqual(report["version"], "2.1.0")
        self.assertEqual(
            report["schema_uri"],
            "https://raw.githubusercontent.com/oasis-tcs/"
            "sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        )
        self.assertEqual(len(report["runs"]), 1)

        run = report["runs"][0]
        driver = run["tool"]["driver"]
        self.assertEqual(driver["name"], "PySpector")
        self.assertIn("version", driver)

        rules = driver["rules"]
        self.assertEqual([rule["id"] for rule in rules], ["PY001", "PY999", "PY010"])
        self.assertEqual(rules[0]["default_configuration"]["level"], "error")
        self.assertEqual(rules[1]["default_configuration"]["level"], "warning")
        self.assertEqual(rules[2]["default_configuration"]["level"], "note")
        self.assertEqual(rules[0]["properties"]["tags"], ["external/cwe/cwe-95"])
        self.assertNotIn("properties", rules[1])

        results = run["results"]
        self.assertEqual(
            [result["rule_id"] for result in results],
            ["PY001", "PY001", "PY999", "PY010"],
        )
        self.assertEqual([result["rule_index"] for result in results], [0, 0, 1, 2])
        self.assertEqual(
            [result["level"] for result in results],
            ["error", "warning", "warning", "note"],
        )

        first_location = results[0]["locations"][0]["physical_location"]
        self.assertEqual(first_location["artifact_location"]["uri"], "src/a.py")
        self.assertEqual(first_location["artifact_location"]["uri_base_id"], "%SRCROOT%")
        self.assertEqual(first_location["region"]["start_line"], 7)
        self.assertEqual(first_location["region"]["snippet"]["text"], "eval(user_input)")
        self.assertEqual(results[0]["message"]["text"], issues[0].description)

    def test_to_html_renders_expected_fields_and_escapes_values(self):
        issue = make_issue(
            description="Unsafe <script>alert(1)</script> & more",
            file_path="src/<danger>&file.py",
            code='<script>alert("x")</script> & value',
            severity="High & Critical",
        )

        output = Reporter([issue], "html").to_html()

        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt; &amp; more", output)
        self.assertIn("src/&lt;danger&gt;&amp;file.py", output)
        self.assertIn("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; value", output)
        self.assertNotIn("<script>alert(1)</script>", output)
        self.assertNotIn('<script>alert("x")</script>', output)

        parser = ReportHtmlParser()
        parser.feed(output)

        self.assertEqual(parser.title.strip(), "PySpector Scan Report")
        self.assertEqual("".join(parser.h1).strip(), "PySpector Scan Report")
        self.assertIn("Found 1 issues.", "".join(parser.h2))
        self.assertEqual(parser.headers, ["File", "Line", "Severity", "Description", "Code"])
        self.assertEqual(
            parser.rows,
            [
                [
                    issue.file_path,
                    str(issue.line_number),
                    issue.severity,
                    issue.description,
                    issue.code,
                ]
            ],
        )

    def test_to_console_reports_no_issues(self):
        self.assertEqual(Reporter([], "console").to_console(), "\nNo issues found.")

    def test_to_console_groups_by_known_severity_and_sorts_within_groups(self):
        issues = [
            make_issue(rule_id="LOW-2", severity=Severity.LOW, file_path="z.py", line_number=2),
            make_issue(rule_id="HIGH-2", severity=Severity.HIGH, file_path="b.py", line_number=9),
            make_issue(
                rule_id="CRITICAL-1",
                severity=Severity.CRITICAL,
                file_path="c.py",
                line_number=1,
            ),
            make_issue(
                rule_id="MEDIUM-1",
                severity=Severity.MEDIUM,
                file_path="m.py",
                line_number=5,
            ),
            make_issue(rule_id="HIGH-1", severity=Severity.HIGH, file_path="a.py", line_number=4),
            make_issue(rule_id="LOW-1", severity=Severity.LOW, file_path="a.py", line_number=3),
            make_issue(
                rule_id="UNKNOWN-1",
                severity="Informational",
                file_path="u.py",
                line_number=1,
            ),
        ]

        output = Reporter(issues, "console").to_console()

        self.assertLess(output.index("CRITICAL (1 issue)"), output.index("HIGH (2 issues)"))
        self.assertLess(output.index("HIGH (2 issues)"), output.index("MEDIUM (1 issue)"))
        self.assertLess(output.index("MEDIUM (1 issue)"), output.index("LOW (2 issues)"))
        self.assertLess(output.index("Rule ID: HIGH-1"), output.index("Rule ID: HIGH-2"))
        self.assertLess(output.index("Rule ID: LOW-1"), output.index("Rule ID: LOW-2"))
        self.assertNotIn("UNKNOWN-1", output)

    def test_generate_dispatches_known_formats_and_defaults_to_console(self):
        issue = make_issue()

        self.assertEqual(
            json.loads(Reporter([issue], "json").generate())["summary"]["issue_count"],
            1,
        )
        self.assertIn("runs", json.loads(Reporter([issue], "sarif").generate()))
        self.assertIn("<html>", Reporter([issue], "html").generate())
        self.assertRegex(Reporter([issue], "unknown").generate(), re.escape("Rule ID: PY001"))


if __name__ == "__main__":
    unittest.main()
