import unittest
import toml
import click
import importlib.resources as pkg_resources

from unittest.mock import patch, mock_open, MagicMock
from pathlib import Path
from pyspector.config import load_config, DEFAULT_CONFIG, get_default_rules

class TestConfig(unittest.TestCase):

    sample_user_config = DEFAULT_CONFIG.copy()
    config_path = Path("/fake/path/config.toml")

    def test_load_config_file_not_exist(self):

        output = load_config(self.config_path)

        self.assertEqual(output, DEFAULT_CONFIG)


    @patch("pathlib.Path.exists", return_value = True)
    @patch("pathlib.Path.open", new_callable=mock_open)
    @patch("toml.load", side_effect=toml.TomlDecodeError("Invalid TOL", doc="", pos=0))
    @patch("click.echo")
    def test_load_config_invalid_toml(self, mock_click_echo, mock_toml_load, mock_file_open, mock_exists):

        output = load_config(self.config_path)

        mock_click_echo.assert_called_once()
        self.assertIn("Warning: Could not parse config file", mock_click_echo.call_args[0][0])

    @patch("pathlib.Path.exists", return_value=True)
    @patch("pathlib.Path.open", new_callable=mock_open)
    @patch("toml.load")
    def test_load_config_valid_toml(self, mock_toml_load, mock_file_open, mock_exists):
        
        mock_toml_load.return_value = {'tool': {'pyspector': self.sample_user_config}}
        
        output = load_config(self.config_path)

        mock_toml_load.assert_called_once()

        expected = DEFAULT_CONFIG.copy()
        expected.update(self.sample_user_config)
        
        self.assertEqual(output, expected)

    @patch("importlib.resources.files", side_effect=FileNotFoundError("File missing"))
    def test_get_default_rules_no_file_found_raises(self, mock_files):
        
        with self.assertRaises(FileNotFoundError) as context:
            get_default_rules(ai_scan=False)

        self.assertIn("Could not load built-in-rules.toml", str(context.exception))
        self.assertIn("File missing", str(context.exception))
        mock_files.assert_called_once_with("pyspector.rules")

    
    @patch("importlib.resources.files")
    def test_file_found_ai_scan_false(self, mock_files):
        
        class MockFile:
            def read_text(self, encoding):
                self.encoding = encoding
                return "toml content"

        mock_files.return_value.joinpath.return_value = MockFile()

        output = get_default_rules(ai_scan=False)

        mock_files.assert_called_once_with("pyspector.rules")
        self.assertEqual(output, "toml content")

    @patch("click.echo")
    @patch("importlib.resources.files")
    def test_file_found_ai_scan_true(self, mock_files, mock_echo):
        
        class MockFile:
            def __init__(self, content):
                self.content = content
            def read_text(self, encoding):
                return self.content

        def joinpath_side_effect(path):
            if path == "built-in-rules.toml":
                return MockFile("base_rules_content")
            elif path == "built-in-rules-ai.toml":
                return MockFile("ai_rules_content")
            else:
                raise FileNotFoundError(f"{path} not found")

        mock_files.return_value.joinpath.side_effect = joinpath_side_effect

        output = get_default_rules(ai_scan=True)

        self.assertEqual(output, "base_rules_content\nai_rules_content")

        mock_echo.assert_called_once_with("[*] AI scanning enabled. Loading additional AI/LLM rules.")

        self.assertEqual(mock_files.call_count, 2)
        mock_files.assert_any_call("pyspector.rules")

if __name__ == "__main__":
    unittest.main()
