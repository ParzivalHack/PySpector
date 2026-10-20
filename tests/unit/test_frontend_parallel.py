"""Tests for the parallel AST front end, the ctx-free AST JSON, and the Rust core's `verbose` flag."""

import ast
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pyspector import _parallel
from pyspector._ast_encode import AstEncoder, describe_problem, parse_and_encode
from pyspector.ast_cache import IncrementalAstCache
from pyspector.cli import get_python_file_asts

CONTEXT_NODES = {"Load", "Store", "Del"}


def _node_types(obj):
    """Every node_type found in an encoded AST (nested dicts/lists)."""
    if isinstance(obj, dict):
        if "node_type" in obj:
            yield obj["node_type"]
        for value in obj.values():
            yield from _node_types(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _node_types(value)


def _force_pool():
    """Patches that let even tiny jobs use a small pool (at most 2 workers)."""
    return (
        patch.object(_parallel, "MIN_TASKS", 2),
        patch.object(_parallel, "MIN_TOTAL_COST", 0),
        patch.object(_parallel, "MAX_WORKERS", 2),
    )


class TestEncoderOmitsContextNodes(unittest.TestCase):
    SRC = "x = y\nobj.attr = items[0]\ndel z\nfor i, j in pairs:\n    pass\n"

    def _types(self):
        return set(_node_types(json.loads(json.dumps(ast.parse(self.SRC), cls=AstEncoder))))

    def test_no_expr_context_nodes_are_emitted(self):
        self.assertTrue(self._types().isdisjoint(CONTEXT_NODES))

    def test_every_other_node_is_still_emitted(self):
        expected = {"Module", "Assign", "Name", "Attribute", "Subscript", "Delete", "For", "Tuple"}
        self.assertTrue(expected <= self._types())


class TestDescribeProblem(unittest.TestCase):
    def test_syntax_error(self):
        with self.assertRaises(SyntaxError) as caught:
            ast.parse("def (:")
        kind, msg, lineno = describe_problem(caught.exception)
        self.assertEqual(kind, "syntax")
        self.assertEqual(msg, caught.exception.msg)
        self.assertEqual(lineno, caught.exception.lineno)

    def test_unicode_error(self):
        with self.assertRaises(UnicodeDecodeError) as caught:
            b"\xff\xfe".decode("utf-8")
        self.assertEqual(
            describe_problem(caught.exception), ("unicode", caught.exception.reason, None)
        )

    def test_anything_else(self):
        self.assertEqual(describe_problem(ValueError("boom")), ("error", "boom", None))


class TestParseAndEncode(unittest.TestCase):
    def test_returns_module_json(self):
        self.assertEqual(json.loads(parse_and_encode("a.py", "x = 1\n"))["node_type"], "Module")

    def test_syntax_error_is_raised(self):
        with self.assertRaises(SyntaxError):
            parse_and_encode("a.py", "def (:")


class TestParallelMap(unittest.TestCase):
    def test_few_tasks_stay_in_process(self):
        self.assertIsNone(_parallel.parallel_map(abs, list(range(_parallel.MIN_TASKS - 1))))

    def test_little_work_stays_in_process(self):
        tasks = list(range(_parallel.MIN_TASKS))
        self.assertIsNone(_parallel.parallel_map(abs, tasks, costs=[1] * len(tasks)))

    def test_environment_can_disable_the_pool(self):
        a, b, c = _force_pool()
        with a, b, c, patch.dict(os.environ, {"PYSPECTOR_NO_PARALLEL": "1"}):
            self.assertIsNone(_parallel.parallel_map(abs, [-1, -2, -3, -4]))

    def test_which_environment_values_disable_the_pool(self):
        for value in ("1", "true", "YES", "on"):
            with (
                self.subTest(value=value),
                patch.dict(os.environ, {"PYSPECTOR_NO_PARALLEL": value}),
            ):
                self.assertTrue(_parallel._disabled_by_environment())
        for value in ("", "0", "false", "No", "off", "  "):
            with (
                self.subTest(value=value),
                patch.dict(os.environ, {"PYSPECTOR_NO_PARALLEL": value}),
            ):
                self.assertFalse(_parallel._disabled_by_environment())
        with patch.dict(os.environ):
            os.environ.pop("PYSPECTOR_NO_PARALLEL", None)
            self.assertFalse(_parallel._disabled_by_environment())

    def test_results_come_back_in_input_order(self):
        tasks = [-i for i in range(40)]
        costs = [(i * 7) % 11 for i in range(40)]  # scrambles the scheduling order
        notes = []
        a, b, c = _force_pool()
        with a, b, c:
            result = _parallel.parallel_map(abs, tasks, costs=costs, on_note=notes.append)
        if result is None:
            self.skipTest(f"process pool unavailable here: {notes}")
        self.assertEqual(result, [abs(t) for t in tasks])


class TestBatchAstJson(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, name, text):
        path = self.tmp / name
        path.write_text(text, encoding="utf-8")
        return path

    def _items(self, count):
        items = []
        for i in range(count):
            source = f"def f{i}(x):\n    return x + {i}\n"
            items.append((self._write(f"m{i}.py", source), source))
        return items

    def test_matches_get_ast_json_and_reports_syntax_errors(self):
        items = self._items(3)
        bad_source = "def (:\n"
        bad = self._write("bad.py", bad_source)
        batch_cache = IncrementalAstCache(cache_dir=self.tmp / "batch")
        outcomes = batch_cache.get_ast_json_batch(items + [(bad, bad_source)])

        reference = IncrementalAstCache(cache_dir=self.tmp / "reference")
        for (path, content), outcome in zip(items, outcomes[:3]):
            self.assertEqual(json.loads(outcome), json.loads(reference.get_ast_json(path, content)))

        kind, _msg, lineno = outcomes[3]
        self.assertEqual((kind, lineno), ("syntax", 1))
        self.assertNotIn(str(bad.resolve()), batch_cache._l1)  # a failed build is never cached

    def test_second_call_is_served_from_the_cache(self):
        items = self._items(3)
        cache = IncrementalAstCache(cache_dir=self.tmp / "cache")
        first = cache.get_ast_json_batch(items)
        with patch.object(IncrementalAstCache, "_build", side_effect=AssertionError("rebuilt")):
            second = cache.get_ast_json_batch(items)
        self.assertEqual(first, second)

    def test_workers_build_and_persist_entries(self):
        items = self._items(6)
        cache = IncrementalAstCache(cache_dir=self.tmp / "cache")
        notes = []
        a, b, c = _force_pool()
        with a, b, c:
            outcomes = cache.get_ast_json_batch(items, parallel=True, on_note=notes.append)
        if notes:
            self.skipTest(f"process pool unavailable here: {notes}")

        reference = IncrementalAstCache(cache_dir=None)
        for (path, content), outcome in zip(items, outcomes):
            self.assertEqual(json.loads(outcome), json.loads(reference.get_ast_json(path, content)))
            self.assertIn(str(path.resolve()), cache._l1)  # the parent keeps L1 warm (watch mode)
            disk_path = cache._disk_path(path)
            self.assertTrue(disk_path is not None and disk_path.exists())  # written by the worker


class TestGetPythonFileAstsParallel(unittest.TestCase):
    def test_parallel_and_sequential_results_are_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for i in range(24):
                (root / f"mod{i}.py").write_text(
                    f"def f{i}(a):\n    return a * {i}\n", encoding="utf-8"
                )
            (root / "broken.py").write_text("def (:\n", encoding="utf-8")

            sequential = get_python_file_asts(root)
            a, b, c = _force_pool()
            with a, b, c:
                parallel = get_python_file_asts(root, parallel=True)

            self.assertEqual(len(sequential), 24)  # the broken file is reported and left out
            self.assertEqual(sequential, parallel)  # same files, same order, same JSON


def _capture_fd1(fn):
    """Run fn() and return everything written to file descriptor 1 meanwhile (as Rust's println! does)."""
    sys.stdout.flush()
    saved = os.dup(1)
    try:
        with tempfile.TemporaryFile() as tmp:
            os.dup2(tmp.fileno(), 1)
            try:
                fn()
            finally:
                os.dup2(saved, 1)
            tmp.seek(0)
            return tmp.read().decode("utf-8", errors="replace")
    finally:
        os.close(saved)


class TestRustCoreVerbose(unittest.TestCase):
    def _scan(self, **kwargs):
        from pyspector._rust_core import run_scan
        from pyspector.config import get_default_rules

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.py").write_text("x = 1\n", encoding="utf-8")
            files = get_python_file_asts(root)
            return run_scan(str(root), get_default_rules(False), {"exclude": []}, files, **kwargs)

    def test_silent_by_default(self):
        self.assertNotIn("[*] Starting analysis", _capture_fd1(self._scan))

    def test_verbose_prints_progress(self):
        self.assertIn("[*] Starting analysis", _capture_fd1(lambda: self._scan(verbose=True)))

    def test_verbose_does_not_change_the_results(self):
        quiet = sorted((i.rule_id, i.line_number) for i in self._scan())
        holder = []
        _capture_fd1(lambda: holder.append(self._scan(verbose=True)))
        loud = sorted((i.rule_id, i.line_number) for i in holder[0])
        self.assertEqual(quiet, loud)

    def test_supply_chain_accepts_verbose_and_needs_no_network_without_manifests(self):
        from pyspector._rust_core import scan_supply_chain

        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(scan_supply_chain(tmp), [])
            self.assertEqual(scan_supply_chain(tmp, verbose=False), [])


if __name__ == "__main__":
    unittest.main()
