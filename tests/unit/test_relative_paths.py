import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urljoin

import click
from bs4 import BeautifulSoup
from click.testing import CliRunner

from pyspector._rust_core import Issue, Severity, run_scan
from pyspector.ast_cache import IncrementalAstCache
from pyspector.cli import cli
from pyspector.reporting import Reporter
from pyspector.triage import create_fingerprint


class TestRelativePaths(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.file = self.root / "space & folder" / "vulnerable file.py"
        self.file.parent.mkdir()
        self.file.write_text("eval(user_data)\n", encoding="utf-8")
        self.issue = Issue(
            "PY001",
            "Unsafe eval",
            str(self.file),
            1,
            "eval(user_data)",
            Severity.High,
            "High",
            "Avoid eval",
            "CWE-95",
        )
        self.runner = CliRunner()
        self.addCleanup(patch.stopall)
        patch("pyspector.cli._print_banner").start()
        patch("pyspector.cli.handle_msg_flag").start()
        patch("pyspector.cli.get_cache", return_value=IncrementalAstCache()).start()
        # The production writer uses sys.__stdout__, which bypasses CliRunner.
        patch("pyspector.cli._write_stdout", side_effect=click.echo).start()

    def invoke(self, args):
        result = self.runner.invoke(cli, args)
        self.assertEqual(result.exit_code, 0, result.output or repr(result.exception))
        return result.output

    def test_boolean_parsing_at_both_option_levels(self):
        cases = [(None, False), ("True", True), ("False", False)]
        for level in ("group", "scan"):
            for value, expected in cases:
                with self.subTest(level=level, value=value):
                    args = ["scan", str(self.root)]
                    if value is not None:
                        args.insert(0 if level == "group" else 1, f"--relative-path={value}")
                    with patch("pyspector.cli._execute_scan") as execute:
                        self.invoke(args)
                    self.assertIs(execute.call_args.kwargs["relative_path"], expected)

    def test_scan_option_overrides_group_option(self):
        with patch("pyspector.cli._execute_scan") as execute:
            self.invoke(["--relative-path=True", "scan", str(self.root), "--relative-path=False"])
        self.assertIs(execute.call_args.kwargs["relative_path"], False)

    def test_help_and_invalid_boolean(self):
        for prefix in ([], ["scan"]):
            with self.subTest(prefix=prefix):
                help_text = self.invoke([*prefix, "--help"])
                self.assertIn("--relative-path BOOLEAN", help_text)
                self.assertIn("[default: False]", help_text)
                self.assertIn("file's parent", help_text)
                result = self.runner.invoke(cli, [*prefix, "--relative-path=invalid"])
                self.assertEqual(result.exit_code, 2)
                self.assertIn("not a valid boolean", result.output)

    def test_wizard_and_repository_forward_the_option(self):
        params = {
            "scan_path": self.root,
            "repo_url": None,
            "ai_scan": False,
            "severity_level": "LOW",
            "report_format": "console",
            "output_file": None,
            "supply_chain_scan": False,
            "syntax_warnings": False,
            "show_stats": False,
            "debug": False,
        }
        for wizard in (False, True):
            for remote in (False, True):
                with self.subTest(wizard=wizard, remote=remote):
                    params["repo_url"] = "https://github.com/example/project" if remote else None
                    args = ["scan", "--relative-path=True"]
                    args += (
                        ["--wizard"]
                        if wizard
                        else (["--url", params["repo_url"]] if remote else [str(self.root)])
                    )
                    with (
                        patch("pyspector.cli.run_wizard", return_value=params),
                        patch("pyspector.cli.subprocess.run") as clone,
                        patch("pyspector.cli._execute_scan") as execute,
                    ):
                        self.invoke(args)
                    self.assertIs(execute.call_args.kwargs["relative_path"], True)
                    self.assertEqual(clone.call_count, int(remote))

    def test_directory_and_single_file_scan_preserve_findings_and_inputs(self):
        for target, expected in (
            (self.root, str(self.file.relative_to(self.root))),
            (self.file, self.file.name),
        ):
            with self.subTest(target=target):
                reports, inputs = [], []
                for option in (None, "False", "True"):
                    args = ["scan", str(target), "-f", "json"]
                    if option is not None:
                        args.append(f"--relative-path={option}")
                    with patch("pyspector.cli.run_scan", wraps=run_scan) as scan:
                        reports.append(json.loads(self.invoke(args)))
                    inputs.append(scan.call_args)
                self.assertGreater(reports[0]["summary"]["issue_count"], 0)
                self.assertEqual(reports[0], reports[1])
                self.assertEqual(inputs[0], inputs[1])
                self.assertEqual(inputs[0], inputs[2])
                self.assertEqual(inputs[0].args[0], str(target.resolve()))
                for absolute, relative in zip(reports[0]["issues"], reports[2]["issues"]):
                    self.assertEqual(absolute["file_path"], str(self.file))
                    self.assertEqual(relative["file_path"], expected)
                    self.assertEqual(
                        {k: v for k, v in absolute.items() if k != "file_path"},
                        {k: v for k, v in relative.items() if k != "file_path"},
                    )
                    self.assertEqual(create_fingerprint(relative), create_fingerprint(absolute))

    def test_report_formats_and_source_identity(self):
        fingerprint = self.issue.get_fingerprint()
        for relative in (False, True):
            expected = str(self.file.relative_to(self.root)) if relative else str(self.file)
            for fmt in ("console", "json", "sarif", "html"):
                with self.subTest(relative=relative, fmt=fmt):
                    output = Reporter(
                        [self.issue], fmt, relative_path=relative, base_path=self.root
                    ).generate()
                    if fmt == "console":
                        self.assertIn(f"File: {expected}:1", output)
                    elif fmt == "json":
                        issue = json.loads(output)["issues"][0]
                        self.assertEqual(issue["file_path"], expected)
                        self.assertEqual(issue["fingerprint"], fingerprint)
                    elif fmt == "html":
                        cells = BeautifulSoup(output, "html.parser").find_all("td")
                        self.assertEqual(cells[0].get_text(), expected)
                        self.assertIn("&amp;", output)
                    else:
                        run = json.loads(output)["runs"][0]
                        artifact = run["results"][0]["locations"][0]["physicalLocation"][
                            "artifactLocation"
                        ]
                        uri = artifact["uri"]
                        self.assertIn("%20", uri)
                        self.assertNotIn(" ", uri)
                        if relative:
                            self.assertEqual(uri, "space%20%26%20folder/vulnerable%20file.py")
                            base = run["originalUriBaseIds"][artifact["uriBaseId"]]["uri"]
                            uri = urljoin(base, uri)
                        else:
                            self.assertEqual(uri, self.file.as_uri())
                            self.assertNotIn("uriBaseId", artifact)
                        self.assertEqual(uri, self.file.as_uri())
                    self.assertEqual(self.issue.file_path, str(self.file))
                    self.assertEqual(self.issue.get_fingerprint(), fingerprint)

    def test_relative_engine_path_is_interpreted_from_working_directory(self):
        relative_source = os.path.relpath(self.file)
        issue = Issue(
            "PY001",
            "Unsafe eval",
            relative_source,
            1,
            "eval(x)",
            Severity.High,
            "High",
            "Avoid eval",
        )
        for relative in (False, True):
            report = Reporter([issue], "json", relative_path=relative, base_path=self.root)
            path = json.loads(report.generate())["issues"][0]["file_path"]
            self.assertEqual(
                path, str(self.file.relative_to(self.root)) if relative else str(self.file)
            )
        self.assertEqual(issue.file_path, relative_source)

    def test_cli_formats_and_report_files(self):
        for fmt in ("console", "json", "sarif", "html"):
            with self.subTest(fmt=fmt):
                report_file = self.root.parent / f"{self.root.name}-{fmt}.report"
                self.addCleanup(report_file.unlink, missing_ok=True)
                self.invoke(
                    [
                        "scan",
                        str(self.root),
                        "--relative-path=True",
                        "-f",
                        fmt,
                        "-o",
                        str(report_file),
                    ]
                )
                output = report_file.read_text(encoding="utf-8")
                if fmt == "json":
                    self.assertEqual(
                        json.loads(output)["issues"][0]["file_path"],
                        str(self.file.relative_to(self.root)),
                    )
                elif fmt == "sarif":
                    artifact = json.loads(output)["runs"][0]["results"][0]["locations"][0][
                        "physicalLocation"
                    ]["artifactLocation"]
                    self.assertEqual(artifact["uri"], "space%20%26%20folder/vulnerable%20file.py")
                elif fmt == "html":
                    self.assertEqual(
                        BeautifulSoup(output, "html.parser").find("td").get_text(),
                        str(self.file.relative_to(self.root)),
                    )
                else:
                    self.assertIn(f"File: {self.file.relative_to(self.root)}:", output)

    def test_baselines_and_severity_filters_are_independent_of_display(self):
        absolute = json.loads(self.invoke(["scan", str(self.root), "-f", "json"]))
        (self.root / ".pyspector_baseline.json").write_text(
            json.dumps(
                {
                    "ignored_fingerprints": [
                        create_fingerprint(issue) for issue in absolute["issues"]
                    ]
                }
            ),
            encoding="utf-8",
        )
        for option in ("False", "True"):
            report = json.loads(
                self.invoke(["scan", str(self.root), "-f", "json", f"--relative-path={option}"])
            )
            self.assertEqual(report["issues"], [])
        (self.root / ".pyspector_baseline.json").unlink()
        for option in ("False", "True"):
            report = json.loads(
                self.invoke(
                    [
                        "scan",
                        str(self.root),
                        "-f",
                        "json",
                        "-s",
                        "CRITICAL",
                        f"--relative-path={option}",
                    ]
                )
            )
            self.assertEqual(report["issues"], [])

    def test_supply_chain_paths_without_network(self):
        vulnerability = {
            "severity": "HIGH",
            "dependency": "example",
            "version": "1",
            "vulnerability_id": "LOCAL-1",
            "file": str(self.file),
            "summary": "Local fixture",
        }
        for relative in (False, True):
            with patch("pyspector._rust_core.scan_supply_chain", return_value=[vulnerability]):
                output = self.invoke(
                    ["scan", str(self.root), "--supply-chain", f"--relative-path={relative}"]
                )
            expected = self.file.relative_to(self.root) if relative else self.file
            self.assertIn(f"File: {expected}", output)
        self.assertEqual(vulnerability["file"], str(self.file))

    def test_old_json_triage_fingerprint_remains_compatible(self):
        old_issue = {
            "rule_id": self.issue.rule_id,
            "file_path": self.issue.file_path,
            "line_number": self.issue.line_number,
            "code": self.issue.code,
        }
        self.assertEqual(create_fingerprint(old_issue), self.issue.get_fingerprint())

    def test_json_uses_the_scanners_original_fingerprint(self):
        # Python and Rust trim different control characters. Rehashing a
        # display record must not override the identity supplied by the engine.
        issue = Issue(
            "PY001",
            "Unsafe eval",
            str(self.file),
            1,
            "\x1ceval(x)\x1c",
            Severity.High,
            "High",
            "Avoid eval",
        )
        output = Reporter([issue], "json", relative_path=True, base_path=self.root).generate()
        record = json.loads(output)["issues"][0]
        self.assertEqual(record["fingerprint"], issue.get_fingerprint())
        self.assertEqual(create_fingerprint(record), issue.get_fingerprint())


if __name__ == "__main__":
    unittest.main()
