import unittest
import json

from bs4 import BeautifulSoup
from types import SimpleNamespace
from pyspector.reporting import Reporter

class TestReporter(unittest.TestCase):

    test_issue = SimpleNamespace(
        rule_id="PY001",
        description="Use of 'eval()' is highly dangerous.",
        file_path="path/to/file.py",
        line_number=1,
        code='eval("a=5 print(a)")',
        severity="High",
        remediation="Avoid 'eval()'. Use safer alternatives like 'ast.literal_eval' for data parsing."
    )

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


    def test_to_sarif(self):
        reporter = Reporter([self.test_issue], "sarif")
        output = reporter.to_sarif()

        output_json = json.loads(output)

        # Check top level SARIF fields
        self.assertEqual(output_json.get("version"), "2.1.0")
        self.assertEqual(output_json.get("schema_uri"), "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json")

        # Check runs
        self.assertIn("runs", output_json)
        self.assertIsInstance(output_json["runs"], list)
        self.assertEqual(len(output_json["runs"]), 1)

        # Check unique single run
        run = output_json["runs"][0]
        self.assertEqual(run["tool"]["driver"]["id"], "pyspector")
        self.assertEqual(run["tool"]["driver"]["name"], "PySpector")

        # Check run results
        self.assertIn("results", run)
        self.assertIsInstance(run["results"], list)
        self.assertEqual(len(run["results"]), 1)

        # Check single run result
        result = run["results"][0]

        # Check rule id
        self.assertEqual(result.get("rule_id"), self.test_issue.rule_id)
        self.assertEqual(result.get("kind"), "fail")
        
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

if __name__ == "__main__":
    unittest.main()
