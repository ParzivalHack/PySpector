import tempfile
import unittest
from pathlib import Path

from pyspector.triage import resolve_baseline_path


class TestResolveBaselinePath(unittest.TestCase):

    def test_uses_scan_root_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            root.mkdir()
            report = Path(tmp) / "report.json"

            self.assertEqual(
                resolve_baseline_path(report, str(root)),
                root / ".pyspector_baseline.json",
            )

    def test_uses_parent_for_a_scanned_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            root.mkdir()
            target = root / "app.py"
            target.write_text("eval(x)\n", encoding="utf-8")
            report = Path(tmp) / "report.json"

            self.assertEqual(
                resolve_baseline_path(report, str(target)),
                root / ".pyspector_baseline.json",
            )

    def test_falls_back_when_scan_root_no_longer_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"

            self.assertEqual(
                resolve_baseline_path(report, str(Path(tmp) / "gone")),
                report.parent / ".pyspector_baseline.json",
            )

    def test_falls_back_when_report_has_no_scan_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "reports" / "report.json"

            self.assertEqual(
                resolve_baseline_path(report, None),
                report.parent / ".pyspector_baseline.json",
            )


if __name__ == "__main__":
    unittest.main()
