import os
import sys
import tempfile
import unittest
from pathlib import Path

from pyspector.cli import get_python_file_asts


@unittest.skipIf(sys.platform == "win32", "symlink creation needs privileges on Windows")
class TestSymlinkContainment(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.scan_root = base / "scanroot"
        self.outside = base / "outside"
        self.scan_root.mkdir()
        self.outside.mkdir()

        self.inside_file = self.scan_root / "app.py"
        self.inside_file.write_text('eval("INSIDE" + x)\n', encoding="utf-8")

        self.canary = self.outside / "canary.py"
        self.canary.write_text('eval("CANARY-OUTSIDE-ROOT" + x)\n', encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def _scanned_paths(self):
        return {r["file_path"] for r in get_python_file_asts(self.scan_root)}

    def test_symlinked_file_pointing_outside_is_not_scanned(self):
        os.symlink(self.canary, self.scan_root / "vendored.py")

        paths = self._scanned_paths()

        self.assertIn(str(self.inside_file.resolve()), paths)
        self.assertNotIn(str(self.canary.resolve()), paths)

    def test_symlinked_directory_pointing_outside_is_not_scanned(self):
        os.symlink(self.outside, self.scan_root / "vendor")

        paths = self._scanned_paths()

        self.assertIn(str(self.inside_file.resolve()), paths)
        self.assertNotIn(str(self.canary.resolve()), paths)

    def test_symlink_that_stays_inside_the_root_is_still_scanned(self):
        target = self.scan_root / "pkg" / "real.py"
        target.parent.mkdir()
        target.write_text('eval("STILL-INSIDE" + x)\n', encoding="utf-8")
        os.symlink(target, self.scan_root / "alias.py")

        paths = self._scanned_paths()

        self.assertIn(str(target.resolve()), paths)

    def test_broken_symlink_does_not_raise(self):
        os.symlink(self.outside / "does-not-exist.py", self.scan_root / "dangling.py")

        paths = self._scanned_paths()

        self.assertIn(str(self.inside_file.resolve()), paths)

    def test_scanning_a_file_directly_still_works(self):
        results = get_python_file_asts(self.canary)

        self.assertEqual([str(self.canary.resolve())], [r["file_path"] for r in results])


if __name__ == "__main__":
    unittest.main()
