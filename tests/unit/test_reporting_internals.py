"""
Tests for pyspector.reporting internals not covered by reporting_test.py.

reporting_test.py exercises to_json and to_sarif. This file adds coverage for
(issue #64): the to_console renderer, the generate() format dispatch, and the
_severity_key / _clean helpers.

Uses SimpleNamespace issues, matching the existing reporting test's style.
"""
import sys
import json
import unittest
from types import SimpleNamespace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from pyspector.reporting import (  # noqa: E402
    Reporter,
    _severity_key,
    _clean,
    _get_version,
)


def issue(severity="HIGH", file_path="a.py", line_number=1,
          rule_id="PY001", description="desc", code="eval('x')"):
    return SimpleNamespace(
        severity=severity, file_path=file_path, line_number=line_number,
        rule_id=rule_id, description=description, code=code,
        remediation="do better",
    )


class TestSeverityKey(unittest.TestCase):
    def test_plain_string_is_uppercased(self):
        self.assertEqual(_severity_key(issue(severity="High")), "HIGH")

    def test_enum_like_value_is_normalized(self):
        # "Severity.CRITICAL" -> "CRITICAL"
        self.assertEqual(_severity_key(issue(severity="Severity.CRITICAL")), "CRITICAL")


class TestClean(unittest.TestCase):
    def test_strips_none_from_dict(self):
        self.assertEqual(_clean({"a": 1, "b": None}), {"a": 1})

    def test_recurses_into_lists(self):
        self.assertEqual(_clean([{"a": None, "b": 2}]), [{"b": 2}])

    def test_unwraps_objects_via_dunder_dict(self):
        self.assertEqual(_clean(SimpleNamespace(x=1, y=None)), {"x": 1})

    def test_passes_scalars_through(self):
        self.assertEqual(_clean(5), 5)
        self.assertEqual(_clean("s"), "s")


class TestToConsole(unittest.TestCase):
    def test_empty_reports_no_issues(self):
        self.assertEqual(Reporter([], "console").to_console(), "\nNo issues found.")

    def test_groups_by_severity_in_order(self):
        out = Reporter(
            [issue(severity="LOW", rule_id="L1"),
             issue(severity="HIGH", rule_id="H1")],
            "console",
        ).to_console()
        self.assertIn("HIGH (1 issue)", out)
        self.assertIn("LOW (1 issue)", out)
        self.assertLess(out.index("HIGH"), out.index("LOW"))

    def test_sorts_within_severity_by_file_then_line(self):
        out = Reporter(
            [issue(severity="HIGH", rule_id="LATE", file_path="a.py", line_number=9),
             issue(severity="HIGH", rule_id="EARLY", file_path="a.py", line_number=2)],
            "console",
        ).to_console()
        self.assertLess(out.index("EARLY"), out.index("LATE"))

    def test_pluralizes_count(self):
        out = Reporter([issue(rule_id="A"), issue(rule_id="B")], "console").to_console()
        self.assertIn("HIGH (2 issues)", out)


class TestGenerateDispatch(unittest.TestCase):
    def test_json_format_returns_valid_json(self):
        out = Reporter([], "json").generate()
        self.assertEqual(json.loads(out)["summary"]["issue_count"], 0)

    def test_unknown_format_falls_back_to_console(self):
        self.assertEqual(Reporter([], "totally-unknown").generate(), "\nNo issues found.")

    def test_console_format_routes_to_console(self):
        self.assertEqual(Reporter([], "console").generate(), "\nNo issues found.")


class TestVersion(unittest.TestCase):
    def test_returns_nonempty_string(self):
        v = _get_version()
        self.assertIsInstance(v, str)
        self.assertTrue(v)


if __name__ == "__main__":
    unittest.main()
