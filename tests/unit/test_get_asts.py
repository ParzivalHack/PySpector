import unittest
import tempfile
import json
from pathlib import Path
from unittest.mock import patch, call

from pyspector.cli import get_python_file_asts


class TestGetPythonFileAsts(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory structure for tests
        self.test_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.test_dir.name)

        # Valid python file
        self.valid_file = self.base_path / "valid.py"
        self.valid_file.write_text("x = 10", encoding="utf-8")

        # Syntax warning file
        self.warning_syntax = self.base_path / "warning_err.py"
        self.warning_syntax.write_bytes(b'path = "c:\windows"')

        # Invalid syntax file
        self.invalid_syntax = self.base_path / "syntax_err.py"
        self.invalid_syntax.write_text("def broken_function(:", encoding="utf-8")

        # Encoding error file
        self.encoding_err = self.base_path / "encoding_err.py"
        self.encoding_err.write_bytes(b"\xff\xfe\x00\x00")

        # Fixture file (should be skipped)
        self.fixture_dir = self.base_path / "tests" / "fixtures"
        self.fixture_dir.mkdir(parents=True)
        self.fixture_file = self.fixture_dir / "fixture_file.py"
        self.fixture_file.write_text("y = 20", encoding="utf-8")

    def tearDown(self):
        self.test_dir.cleanup()

    # @patch('pyspector.cli.click.echo')
    # @patch('pyspector.cli.click.style', side_effect=lambda msg, fg=None, **kwargs: msg)
    def test_get_python_file_asts_handling_default(self):
        """Test that by default SyntaxWarnings are ignored and files are included."""
        # Run function with default (enable_syntax_warnings=False)
        results = get_python_file_asts(self.base_path)
        
        # We expect BOTH the valid python file AND the warning file to be in the result
        # because the warning is ignored and parsing proceeds.
        self.assertEqual(len(results), 2)
        filenames = [r["file_path"] for r in results]
        self.assertIn("valid.py", filenames)
        self.assertIn("warning_err.py", filenames)

    def test_get_python_file_asts_handling_enabled(self):
        """Test that when enabled, SyntaxWarnings are treated as errors and files are excluded."""
        # Run function with enable_syntax_warnings=True
        results = get_python_file_asts(self.base_path, enable_syntax_warnings=True)
        
        # We expect ONLY the valid python file to be in the result
        # because the warning_err.py triggers an exception and is caught.
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["file_path"], "valid.py")
        self.assertEqual(results[0]["content"], "x = 10")
        self.assertIn("ast_json", results[0])

        # Verify JSON properties exist
        ast_obj = json.loads(results[0]["ast_json"])
        self.assertEqual(ast_obj["node_type"], "Module")


if __name__ == "__main__":
    unittest.main()
