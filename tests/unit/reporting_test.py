import unittest
import json

from bs4 import BeautifulSoup
from types import SimpleNamespace
from pyspector.reporting import Reporter


def _make_issue(
    rule_id="PY001",
    description="Use of 'eval()' is highly dangerous.",
    file_path="path/to/file.py",
    line_number=1,
    code='eval("a=5 print(a)")',
    severity="High",
    remediation="Avoid 'eval()'. Use safer alternatives like 'ast.literal_eval' for data parsing.",
    cwe="CWE-95",
):
    return SimpleNamespace(
        rule_id=rule_id,
        description=description,
        file_path=file_path,
        line_number=line_number,
        code=code,
        severity=severity,
        remediation=remediation,
        cwe=cwe,
    )


class TestReporter(unittest.TestCase):

    test_issue = _make_issue()

    # ------------------------------------------------------------------ #
    #  JSON                                                              #
    # ------------------------------------------------------------------ #

    def test_to_json(self):
        reporter = Reporter([self.test_issue], "json")
        output = reporter.to_json()

        output_json = json.loads(output)
        
        # Check issues summary
        self.assertEqual(output_json["summary"]["issue_count"], 1)

        # Check issue fields
        issue_json = output_json["issues"][0]
        self.assertEqual(issue_json["rule_id"], self.test_issue.rule_id)
        self.assertEqual(issue_json["description"], self.test_issue.description)
        self.assertEqual(issue_json["file_path"], self.test_issue.file_path)
        self.assertEqual(issue_json["line_number"], self.test_issue.line_number)
        self.assertEqual(issue_json["code"], self.test_issue.code)
        self.assertEqual(issue_json["severity"], self.test_issue.severity)
        self.assertEqual(issue_json["remediation"], self.test_issue.remediation)

    def test_to_json_issue_count_matches_actual_issues(self):
        issues = [_make_issue(rule_id=f"PY{i:03d}") for i in range(5)]
        reporter = Reporter(issues, "json")
        output_json = json.loads(reporter.to_json())
        self.assertEqual(output_json["summary"]["issue_count"], 5)
        self.assertEqual(len(output_json["issues"]), 5)

    def test_to_json_includes_cwe_field(self):
        issue = _make_issue(cwe="CWE-78")
        reporter = Reporter([issue], "json")
        output_json = json.loads(reporter.to_json())
        self.assertEqual(output_json["issues"][0]["cwe"], "CWE-78")

    # ------------------------------------------------------------------ #
    #  SARIF                                                             #
    # ------------------------------------------------------------------ #

    def test_to_sarif(self):
        reporter = Reporter([self.test_issue], "sarif")
        output = reporter.to_sarif()

        output_json = json.loads(output)

        # Check top level SARIF fields
        self.assertEqual(output_json.get("version"), "2.1.0")
        self.assertEqual(
            output_json.get("schema_uri"),
            "https://raw.githubusercontent.com/oasis-tcs/"
            "sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        )

        # Check runs
        self.assertIn("runs", output_json)
        self.assertIsInstance(output_json["runs"], list)
        self.assertEqual(len(output_json["runs"]), 1)

        # Check unique single run
        run = output_json["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "PySpector")

        # Check run results
        self.assertIn("results", run)
        self.assertIsInstance(run["results"], list)
        self.assertEqual(len(run["results"]), 1)

        # Check single run result
        result = run["results"][0]

        # Check rule id
        self.assertEqual(result.get("rule_id"), self.test_issue.rule_id)
        
        # Check description
        self.assertIn("message", result)
        self.assertEqual(result["message"].get("text"), self.test_issue.description)

        # Check file_path
        self.assertIn("locations", result)
        self.assertIsInstance(result["locations"], list)
        location = result["locations"][0]
        self.assertIn("physical_location", location)
        physical = location["physical_location"]
        self.assertIn("artifact_location", physical)
        artifact = physical["artifact_location"]
        self.assertEqual(artifact.get("uri"), self.test_issue.file_path)

    def test_to_sarif_result_has_level_field(self):
        reporter = Reporter([self.test_issue], "sarif")
        output_json = json.loads(reporter.to_json())
        result = output_json["runs"][0]["results"][0]
        self.assertIn("level", result)
        # HIGH severity maps to "error" in SARIF
        self.assertEqual(result["level"], "error")

    def test_to_sarif_result_has_rule_index(self):
        reporter = Reporter([self.test_issue], "sarif")
        output_json = json.loads(reporter.to_json())
        result = output_json["runs"][0]["results"][0]
        self.assertIn("ruleIndex", result)
        self.assertIsInstance(result["ruleIndex"], int)

    def test_to_sarif_rules_contain_external_cwe_tag(self):
        issue = _make_issue(cwe="CWE-78")
        reporter = Reporter([issue], "sarif")
        output_json = json.loads(reporter.to_json())
        rules = output_json["runs"][0]["tool"]["driver"]["rules"]
        self.assertEqual(len(rules), 1)
        rule = rules[0]
        self.assertIn("properties", rule)
        tags = rule["properties"].get("tags", [])
        self.assertIn("external/cwe/cwe-78", tags)

    def test_to_sarif_rule_without_cwe_has_no_tags_property(self):
        issue = _make_issue(cwe=None)
        reporter = Reporter([issue], "sarif")
        output_json = json.loads(reporter.to_json())
        rules = output_json["runs"][0]["tool"]["driver"]["rules"]
        rule = rules[0]
        # properties should be None (cleaned up by _clean)
        self.assertNotIn("properties", rule)

    def test_to_sarif_multiple_issues_same_rule_share_rule_entry(self):
        issues = [
            _make_issue(rule_id="PY001"),
            _make_issue(rule_id="PY001"),
            _make_issue(rule_id="PY002"),
        ]
        reporter = Reporter(issues, "sarif")
        output_json = json.loads(reporter.to_json())
        rules = output_json["runs"][0]["tool"]["driver"]["rules"]
        # Should only have 2 unique rules
        self.assertEqual(len(rules), 2)
        rule_ids = [r["id"] for r in rules]
        self.assertCountEqual(rule_ids, ["PY001", "PY002"])

    def test_to_sarif_severity_levels_map_correctly(self):
        cases = [
            ("CRITICAL", "error"),
            ("HIGH", "error"),
            ("MEDIUM", "warning"),
            ("LOW", "note"),
        ]
        for sev, expected_level in cases:
            issue = _make_issue(severity=sev)
            reporter = Reporter([issue], "sarif")
            output_json = json.loads(reporter.to_json())
            result = output_json["runs"][0]["results"][0]
            self.assertEqual(
                result["level"],
                expected_level,
                f"severity {sev} should map to {expected_level}",
            )

    # ------------------------------------------------------------------ #
    #  HTML                                                              #
    # ------------------------------------------------------------------ #

    def test_to_html(self):
        reporter = Reporter([self.test_issue], "html")
        output = reporter.to_html()

        soup = BeautifulSoup(output, "html.parser")

        self.assertEqual(soup.title.string, "PySpector Scan Report")
        
        # Check header h1
        h1 = soup.find("h1")
        self.assertIsNotNone(h1)
        self.assertEqual(h1.text.strip(), "PySpector Scan Report")

        # Check header h2
        h2 = soup.find("h2")
        self.assertIsNotNone(h2)
        self.assertIn("Found 1 issues.", h2.text)

        # Check table
        table = soup.find("table")
        self.assertIsNotNone(table)

        # Check table header
        headers = [th.text.strip() for th in table.find_all("th")]
        expected_headers = ["File", "Line", "Severity", "Description", "Code"]
        self.assertEqual(headers, expected_headers)

        rows = table.find_all("tr")[1:]
        self.assertEqual(len(rows), 1)

        # Check result row
        cells = rows[0].find_all("td")
        self.assertEqual(cells[0].text.strip(), self.test_issue.file_path)
        self.assertEqual(cells[1].text.strip(), str(self.test_issue.line_number))
        self.assertEqual(cells[2].text.strip(), self.test_issue.severity)
        self.assertEqual(cells[3].text.strip(), self.test_issue.description)
        
        code_cell = cells[4].find("code")
        self.assertIsNotNone(code_cell)
        self.assertEqual(code_cell.text.strip(), self.test_issue.code)

    def test_to_html_issue_count_in_header(self):
        issues = [_make_issue(rule_id=f"PY{i:03d}") for i in range(3)]
        reporter = Reporter(issues, "html")
        soup = BeautifulSoup(reporter.to_html(), "html.parser")
        h2 = soup.find("h2")
        self.assertIn("Found 3 issues.", h2.text)

    def test_to_html_escape_injects_html_safely(self):
        issue = _make_issue(description="<script>alert('xss')</script>")
        reporter = Reporter([issue], "html")
        output = reporter.to_html()
        self.assertNotIn("<script>", output)
        self.assertIn("&lt;script&gt;", output)

    # ------------------------------------------------------------------ #
    #  Console                                                           #
    # ------------------------------------------------------------------ #

    def test_to_console_empty_issues(self):
        reporter = Reporter([], "console")
        output = reporter.to_console()
        self.assertIn("No issues found.", output)

    def test_to_console_sorted_by_file_and_line(self):
        issues = [
            _make_issue(file_path="b.py", line_number=10),
            _make_issue(file_path="a.py", line_number=5),
            _make_issue(file_path="a.py", line_number=3),
        ]
        reporter = Reporter(issues, "console")
        output = reporter.to_console()
        # a.py:3 should appear before a.py:5, which should appear before b.py:10
        idx_a3 = output.find("a.py:3")
        idx_a5 = output.find("a.py:5")
        idx_b10 = output.find("b.py:10")
        self.assertLess(idx_a3, idx_a5)
        self.assertLess(idx_a5, idx_b10)

    def test_to_console_groups_by_severity(self):
        issues = [
            _make_issue(severity="LOW"),
            _make_issue(severity="CRITICAL"),
            _make_issue(severity="MEDIUM"),
            _make_issue(severity="HIGH"),
        ]
        reporter = Reporter(issues, "console")
        output = reporter.to_console()
        idx_critical = output.find("CRITICAL")
        idx_high = output.find("HIGH")
        idx_medium = output.find("MEDIUM")
        idx_low = output.find("LOW")
        self.assertLess(idx_critical, idx_high)
        self.assertLess(idx_high, idx_medium)
        self.assertLess(idx_medium, idx_low)

    def test_to_console_pluralization(self):
        issues = [_make_issue(rule_id=f"PY{i:03d}") for i in range(2)]
        reporter = Reporter(issues, "console")
        output = reporter.to_console()
        self.assertIn("2 issues", output)

    def test_to_console_singular(self):
        reporter = Reporter([_make_issue()], "console")
        output = reporter.to_console()
        self.assertIn("1 issue", output)

    def test_to_console_shows_rule_id_and_code(self):
        reporter = Reporter([_make_issue()], "console")
        output = reporter.to_console()
        self.assertIn("Rule ID: PY001", output)
        self.assertIn('eval("a=5 print(a)")', output)

    # ------------------------------------------------------------------ #
    #  generate()                                                        #
    # ------------------------------------------------------------------ #

    def test_generate_routes_to_correct_format(self):
        issue = _make_issue()
        for fmt in ("json", "sarif", "html", "console"):
            reporter = Reporter([issue], fmt)
            output = reporter.generate()
            self.assertIsInstance(output, str)
            self.assertGreater(len(output), 0)

    def test_generate_unknown_format_falls_back_to_console(self):
        reporter = Reporter([_make_issue()], "unknown")
        output = reporter.generate()
        # Should fall back to console output
        self.assertIn("Rule ID:", output)


if __name__ == "__main__":
    unittest.main()
