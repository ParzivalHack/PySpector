import ast
import hashlib
import json
import os
import tempfile
import unittest
import warnings
import zlib
from pathlib import Path
from unittest.mock import patch

from pyspector._ast_encode import AstEncoder, encode_node
from pyspector.ast_cache import (
    CACHE_VERSION,
    AstChunk,
    FileCacheEntry,
    IncrementalAstCache,
    MAX_L1_ENTRIES,
    _assemble_module_json,
    _build_ast_json_and_chunks,
    _deserialize_entry,
    _make_chunk_id,
    _reset_cache_singleton,
    _serialize_entry,
    get_cache,
)


def _parse_json(ast_json: str) -> dict:
    return json.loads(ast_json)


def _make_cache(tmp: Path, max_l1: int = MAX_L1_ENTRIES) -> IncrementalAstCache:
    return IncrementalAstCache(cache_dir=tmp / "cache", max_l1_entries=max_l1)


# ── TestChunkIds ──────────────────────────────────────────────────────────────


class TestChunkIds(unittest.TestCase):
    def _ids(self, source: str) -> list:
        tree = ast.parse(source)
        seen: dict = {}
        return [_make_chunk_id(n, seen) for n in tree.body]

    def test_function(self):
        self.assertEqual(self._ids("def foo(): pass"), ["FunctionDef:foo"])

    def test_async_function(self):
        self.assertEqual(self._ids("async def bar(): pass"), ["AsyncFunctionDef:bar"])

    def test_class(self):
        self.assertEqual(self._ids("class MyClass: pass"), ["ClassDef:MyClass"])

    def test_bare_statement(self):
        self.assertEqual(self._ids("x = 1"), ["stmt:1"])

    def test_duplicate_names_get_suffix(self):
        ids = self._ids("def foo(): pass\ndef foo(): pass")
        self.assertEqual(ids, ["FunctionDef:foo", "FunctionDef:foo:1"])

    def test_mixed(self):
        ids = self._ids("x = 1\ndef foo(): pass\nclass Bar: pass")
        self.assertEqual(ids, ["stmt:1", "FunctionDef:foo", "ClassDef:Bar"])


# ── TestBuildAstJson ─────────────────────────────────────────────────────────


class TestBuildAstJson(unittest.TestCase):
    def _build(self, source: str, old: dict | None = None) -> tuple:
        tree = ast.parse(source)
        return _build_ast_json_and_chunks(tree, source, old or {})

    def test_empty_module(self):
        json_str, chunks = self._build("")
        parsed = _parse_json(json_str)
        self.assertEqual(parsed["node_type"], "Module")
        self.assertEqual(parsed["fields"]["body"], [])
        self.assertEqual(chunks, {})

    def test_single_function_structure(self):
        src = "def foo(x):\n    return x + 1\n"
        json_str, chunks = self._build(src)
        parsed = _parse_json(json_str)
        body = parsed["children"]["body"]
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["node_type"], "FunctionDef")
        self.assertIn("FunctionDef:foo", chunks)

    def test_json_matches_direct_encoder(self):
        src = "x = 1\ndef foo(): pass\nclass Bar: pass\n"
        tree = ast.parse(src)
        direct = json.dumps(tree, cls=AstEncoder)
        incremental, _ = self._build(src)
        self.assertEqual(_parse_json(direct), _parse_json(incremental))

    def test_chunk_reuse_skips_encoding(self):
        src = "def foo(): pass\ndef bar(): pass\n"
        _, old_chunks = self._build(src)

        new_src = "def foo(): pass\ndef bar(): return 42\n"
        new_tree = ast.parse(new_src)
        _, new_chunks = _build_ast_json_and_chunks(new_tree, new_src, old_chunks)

        # Unchanged chunk: identical compressed bytes reused
        self.assertEqual(old_chunks["FunctionDef:foo"].ast_json_z, new_chunks["FunctionDef:foo"].ast_json_z)
        # Changed chunk: different bytes
        self.assertNotEqual(
            old_chunks["FunctionDef:bar"].ast_json_z,
            new_chunks["FunctionDef:bar"].ast_json_z,
        )

    def test_moved_chunk_not_reused(self):
        src = "def foo(): pass\ndef bar(): pass\n"
        _, old_chunks = self._build(src)

        # Insert a line at top → foo shifts to line 2
        new_src = "x = 1\ndef foo(): pass\ndef bar(): pass\n"
        new_tree = ast.parse(new_src)
        _, new_chunks = _build_ast_json_and_chunks(new_tree, new_src, old_chunks)

        # foo moved from line 1 → 2: must NOT reuse
        self.assertNotEqual(
            old_chunks["FunctionDef:foo"].ast_json_z,
            new_chunks["FunctionDef:foo"].ast_json_z,
        )


# ── TestAssembleModuleJson ────────────────────────────────────────────────────


class TestAssembleModuleJson(unittest.TestCase):
    def test_non_empty_body_goes_to_children(self):
        body = ['{"node_type": "Assign"}']
        result = _parse_json(_assemble_module_json(body, []))
        self.assertIn("body", result["children"])
        self.assertNotIn("body", result["fields"])

    def test_empty_body_goes_to_fields(self):
        result = _parse_json(_assemble_module_json([], []))
        self.assertIn("body", result["fields"])
        self.assertEqual(result["fields"]["body"], [])

    def test_non_empty_type_ignores_goes_to_children(self):
        ti = ['{"node_type": "TypeIgnore"}']
        result = _parse_json(_assemble_module_json([], ti))
        self.assertIn("type_ignores", result["children"])

    def test_empty_type_ignores_goes_to_fields(self):
        result = _parse_json(_assemble_module_json([], []))
        self.assertIn("type_ignores", result["fields"])
        self.assertEqual(result["fields"]["type_ignores"], [])

    def test_module_metadata(self):
        result = _parse_json(_assemble_module_json([], []))
        self.assertEqual(result["node_type"], "Module")
        self.assertEqual(result["lineno"], -1)
        self.assertEqual(result["col_offset"], -1)

    def test_output_is_valid_json(self):
        body = ['{"node_type": "Expr", "lineno": 1}']
        json.loads(_assemble_module_json(body, []))  # must not raise


# ── TestSerializeDeserialize ──────────────────────────────────────────────────


class TestSerializeDeserialize(unittest.TestCase):
    def _make_entry(self) -> FileCacheEntry:
        src = "def foo(): pass\n"
        tree = ast.parse(src)
        full_json, chunks = _build_ast_json_and_chunks(tree, src, {})
        return FileCacheEntry(
            file_path="/tmp/test_file.py",
            file_hash=hashlib.sha256(src.encode()).hexdigest(),
            mtime=1234567890.0,
            full_ast_json_z=zlib.compress(full_json.encode()),
            chunks=chunks,
        )

    def test_roundtrip(self):
        entry = self._make_entry()
        restored = _deserialize_entry(_serialize_entry(entry))
        self.assertEqual(restored.file_path, entry.file_path)
        self.assertEqual(restored.file_hash, entry.file_hash)
        self.assertEqual(restored.mtime, entry.mtime)
        self.assertEqual(restored.full_ast_json_z, entry.full_ast_json_z)
        self.assertEqual(restored.version, entry.version)
        self.assertEqual(set(restored.chunks.keys()), set(entry.chunks.keys()))

    def test_serialized_is_json_not_pickle(self):
        entry = self._make_entry()
        raw = _serialize_entry(entry)
        # Must be valid JSON
        d = json.loads(raw)
        self.assertIn("version", d)
        self.assertIn("file_hash", d)
        # Must NOT be a pickle stream (pickle starts with 0x80 or b'\x80')
        self.assertFalse(raw.encode()[0:1] == b'\x80')
        # Must start with '{' (JSON object)
        self.assertEqual(raw[0], '{')

    def test_deserialize_raises_on_garbage(self):
        with self.assertRaises(Exception):
            _deserialize_entry("not json at all }{")


# ── TestIncrementalAstCache ───────────────────────────────────────────────────


class TestIncrementalAstCache(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def _write(self, name: str, content: str) -> Path:
        p = self.tmp / name
        p.write_text(content, encoding="utf-8")
        return p

    def _l1_key(self, p: Path) -> str:
        """Return the L1 dict key for a path (always the resolved form)."""
        return str(p.resolve())

    # ── L1 mtime hit ──────────────────────────────────────────────────────

    def test_l1_mtime_hit_skips_hash(self):
        cache = _make_cache(self.tmp)
        src = "def foo(): pass\n"
        p = self._write("a.py", src)

        cache.get_ast_json(p, src)  # populate L1

        with patch("pyspector.ast_cache.hashlib") as mock_hash:
            cache.get_ast_json(p, src)  # same mtime → must not hash
            mock_hash.sha256.assert_not_called()

    # ── L1 hash hit ───────────────────────────────────────────────────────

    def test_l1_hash_hit_updates_mtime(self):
        cache = _make_cache(self.tmp)
        src = "x = 1\n"
        p = self._write("b.py", src)

        cache.get_ast_json(p, src)
        entry_before = cache._l1[self._l1_key(p)]
        old_mtime = entry_before.mtime

        # Touch the file (change mtime without changing content)
        os.utime(p, (old_mtime + 1, old_mtime + 1))
        cache.get_ast_json(p, src)

        entry_after = cache._l1[self._l1_key(p)]
        self.assertNotEqual(entry_after.mtime, old_mtime)
        # Same bytes object (shallow copy via dataclasses.replace — no rebuild)
        self.assertIs(entry_before.full_ast_json_z, entry_after.full_ast_json_z)

    # ── L2 disk hit ───────────────────────────────────────────────────────

    def test_l2_disk_survives_l1_eviction(self):
        cache = _make_cache(self.tmp)
        src = "def saved(): pass\n"
        p = self._write("c.py", src)

        cache.get_ast_json(p, src)  # write to disk
        cache._l1.clear()           # evict L1

        ast_json = cache.get_ast_json(p, src)  # must load from disk
        self.assertEqual(_parse_json(ast_json)["node_type"], "Module")

    def test_l2_stale_on_content_change(self):
        cache = _make_cache(self.tmp)
        src_v1 = "def foo(): pass\n"
        src_v2 = "def foo(): return 1\n"
        p = self._write("d.py", src_v1)

        cache.get_ast_json(p, src_v1)
        cache._l1.clear()

        p.write_text(src_v2, encoding="utf-8")
        ast_json = cache.get_ast_json(p, src_v2)
        func = _parse_json(ast_json)["children"]["body"][0]
        self.assertEqual(func["node_type"], "FunctionDef")

    # ── Cache version invalidation ────────────────────────────────────────

    def test_stale_version_triggers_rebuild(self):
        cache = _make_cache(self.tmp)
        src = "x = 42\n"
        p = self._write("e.py", src)
        cache.get_ast_json(p, src)

        disk_p = cache._disk_path(p)
        assert disk_p is not None and disk_p.exists()

        # Tamper with version in the JSON cache file
        data = json.loads(disk_p.read_text(encoding="utf-8"))
        data["version"] = 0
        disk_p.write_text(json.dumps(data), encoding="utf-8")

        cache._l1.clear()
        ast_json = cache.get_ast_json(p, src)
        self.assertIn("Module", ast_json)

    # ── SyntaxError propagation ───────────────────────────────────────────

    def test_syntax_error_propagates(self):
        cache = _make_cache(self.tmp)
        p = self._write("bad.py", "def (: pass\n")
        with self.assertRaises(SyntaxError):
            cache.get_ast_json(p, "def (: pass\n")

    def test_syntax_error_not_cached(self):
        cache = _make_cache(self.tmp)
        p = self._write("bad2.py", "def (: pass\n")
        try:
            cache.get_ast_json(p, "def (: pass\n")
        except SyntaxError:
            pass
        self.assertNotIn(self._l1_key(p), cache._l1)

    # ── invalidate() ──────────────────────────────────────────────────────

    def test_invalidate_clears_l1_and_disk(self):
        cache = _make_cache(self.tmp)
        src = "y = 7\n"
        p = self._write("f.py", src)
        cache.get_ast_json(p, src)

        disk_p = cache._disk_path(p)
        assert disk_p is not None and disk_p.exists()

        cache.invalidate(p)
        self.assertNotIn(self._l1_key(p), cache._l1)
        self.assertFalse(disk_p.exists())

    # ── get_changed_chunks() ──────────────────────────────────────────────

    def test_get_changed_chunks_detects_modification(self):
        cache = _make_cache(self.tmp)
        p = self.tmp / "g.py"
        old = "def foo(): pass\ndef bar(): pass\n"
        new = "def foo(): return 1\ndef bar(): pass\n"
        changed = cache.get_changed_chunks(p, old, new)
        self.assertIn("FunctionDef:foo", changed)
        self.assertNotIn("FunctionDef:bar", changed)

    def test_get_changed_chunks_detects_addition(self):
        cache = _make_cache(self.tmp)
        p = self.tmp / "h.py"
        old = "def foo(): pass\n"
        new = "def foo(): pass\ndef baz(): pass\n"
        changed = cache.get_changed_chunks(p, old, new)
        self.assertIn("FunctionDef:baz", changed)

    def test_get_changed_chunks_detects_deletion(self):
        cache = _make_cache(self.tmp)
        p = self.tmp / "i.py"
        old = "def foo(): pass\ndef bar(): pass\n"
        new = "def foo(): pass\n"
        changed = cache.get_changed_chunks(p, old, new)
        self.assertIn("FunctionDef:bar", changed)

    # ── No-disk-cache mode ────────────────────────────────────────────────

    def test_works_without_cache_dir(self):
        cache = IncrementalAstCache(cache_dir=None)
        src = "z = 99\n"
        p = self._write("j.py", src)
        self.assertIn("Module", cache.get_ast_json(p, src))

    # ── Output format ─────────────────────────────────────────────────────

    def test_output_is_valid_json(self):
        cache = _make_cache(self.tmp)
        src = "import os\n\ndef greet(name: str) -> str:\n    return f'hello {name}'\n"
        p = self._write("k.py", src)
        parsed = _parse_json(cache.get_ast_json(p, src))
        self.assertEqual(parsed["node_type"], "Module")

    def test_output_matches_direct_encode(self):
        """Cache output must be semantically identical to direct AstEncoder output."""
        cache = _make_cache(self.tmp)
        src = "x = 1\n\nclass Foo:\n    def method(self): pass\n"
        p = self._write("l.py", src)

        cached = _parse_json(cache.get_ast_json(p, src))
        direct = _parse_json(json.dumps(ast.parse(src), cls=AstEncoder))
        self.assertEqual(cached, direct)

    # ── Security: no pickle in disk cache ─────────────────────────────────

    def test_disk_cache_uses_json_not_pickle(self):
        """Disk cache must store JSON, not pickle (no arbitrary code execution)."""
        cache = _make_cache(self.tmp)
        src = "def secure(): pass\n"
        p = self._write("sec.py", src)
        cache.get_ast_json(p, src)

        disk_p = cache._disk_path(p)
        assert disk_p is not None and disk_p.exists()

        raw = disk_p.read_bytes()
        # JSON object starts with '{'
        self.assertEqual(raw[0:1], b"{")
        # Must be parseable as JSON
        data = json.loads(raw.decode("utf-8"))
        self.assertIn("version", data)
        self.assertIn("file_hash", data)
        self.assertIn("chunks", data)
        # Must NOT be a pickle stream (pickle magic bytes 0x80)
        self.assertNotEqual(raw[0:1], b"\x80")

    def test_disk_cache_file_extension_is_json(self):
        cache = _make_cache(self.tmp)
        p = self._write("ext.py", "x = 1\n")
        disk_p = cache._disk_path(p)
        assert disk_p is not None
        self.assertEqual(disk_p.suffix, ".json")

    def test_corrupted_cache_recovers_gracefully(self):
        """A corrupted JSON cache file must be discarded and rebuilt without error."""
        cache = _make_cache(self.tmp)
        src = "x = 1\n"
        p = self._write("corrupt.py", src)
        cache.get_ast_json(p, src)

        disk_p = cache._disk_path(p)
        assert disk_p is not None
        disk_p.write_text("}{not valid json", encoding="utf-8")

        cache._l1.clear()
        ast_json = cache.get_ast_json(p, src)
        self.assertIn("Module", ast_json)
        # File must be rebuilt after recovery
        self.assertTrue(disk_p.exists())
        self.assertEqual(json.loads(disk_p.read_text(encoding="utf-8"))["version"], CACHE_VERSION)

    # ── Path canonicalization ─────────────────────────────────────────────

    def test_resolved_path_used_as_l1_key(self):
        """The L1 key must always be the resolved (canonical) path."""
        cache = _make_cache(self.tmp)
        src = "def foo(): pass\n"
        p = self._write("canon.py", src)

        cache.get_ast_json(p, src)

        # Key in L1 must be the resolved form
        self.assertIn(str(p.resolve()), cache._l1)

    def test_same_file_via_resolve_hits_same_entry(self):
        """Calling get_ast_json with an already-resolved path must hit L1."""
        cache = _make_cache(self.tmp)
        src = "x = 1\n"
        p = self._write("res.py", src)

        cache.get_ast_json(p, src)
        initial_len = len(cache._l1)

        # Call again with the resolved path — must not create a second entry
        cache.get_ast_json(p.resolve(), src)
        self.assertEqual(len(cache._l1), initial_len)

    # ── L1 LRU eviction ───────────────────────────────────────────────────

    def test_l1_lru_eviction(self):
        """L1 must evict LRU entries when max_l1_entries is exceeded."""
        cache = _make_cache(self.tmp, max_l1=2)

        files = []
        for i in range(3):
            src = f"def f{i}(): pass\n"
            p = self._write(f"lru_{i}.py", src)
            files.append(p)
            cache.get_ast_json(p, src)

        self.assertEqual(len(cache._l1), 2)
        # Most recently used entries should be present
        self.assertIn(str(files[2].resolve()), cache._l1)
        self.assertIn(str(files[1].resolve()), cache._l1)
        # Oldest entry should have been evicted
        self.assertNotIn(str(files[0].resolve()), cache._l1)

    def test_l1_lru_access_updates_recency(self):
        """Accessing an entry should protect it from eviction."""
        cache = _make_cache(self.tmp, max_l1=2)

        files = []
        for i in range(2):
            src = f"def f{i}(): pass\n"
            p = self._write(f"lru_rec_{i}.py", src)
            files.append(p)
            cache.get_ast_json(p, src)

        # Access the first file to make it the most-recently-used
        cache.get_ast_json(files[0], f"def f0(): pass\n")

        # Add a third file, which should evict files[1] (LRU), not files[0]
        src2 = "def f2(): pass\n"
        p2 = self._write("lru_rec_2.py", src2)
        cache.get_ast_json(p2, src2)

        self.assertIn(str(files[0].resolve()), cache._l1)
        self.assertNotIn(str(files[1].resolve()), cache._l1)

    # ── mkdir failure → graceful degradation ──────────────────────────────

    def test_mkdir_failure_degrades_to_no_disk(self):
        """If the cache directory cannot be created, the cache runs L1-only."""
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with patch("pathlib.Path.mkdir", side_effect=OSError("Permission denied")):
                cache = IncrementalAstCache(cache_dir=Path("/fake/no/permission"))

        self.assertIsNone(cache._cache_dir)
        self.assertTrue(any("cache directory" in str(w.message) for w in caught))

        # L1-only mode must still work
        src = "x = 1\n"
        p = self._write("fallback.py", src)
        self.assertIn("Module", cache.get_ast_json(p, src))

    # ── Disk write failure is non-blocking ────────────────────────────────

    def test_disk_write_failure_does_not_crash(self):
        """A disk write failure must issue a warning but not abort the scan."""
        cache = _make_cache(self.tmp)
        src = "def resilient(): pass\n"
        p = self._write("write_fail.py", src)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with patch("pathlib.Path.write_text", side_effect=OSError("disk full")):
                ast_json = cache.get_ast_json(p, src)

        self.assertIn("Module", ast_json)
        # A warning must have been issued
        self.assertTrue(any("cache" in str(w.message).lower() for w in caught))

    # ── Encoder parity ────────────────────────────────────────────────────

    def test_cache_output_matches_ast_encoder(self):
        """The cache path and the direct AstEncoder path must be identical."""
        cache = _make_cache(self.tmp)
        src = (
            "import os\n\n"
            "CONST = 42\n\n"
            "class Processor:\n"
            "    def run(self, data: list) -> dict:\n"
            "        return {str(i): v for i, v in enumerate(data)}\n"
        )
        p = self._write("parity.py", src)

        cached = _parse_json(cache.get_ast_json(p, src))
        direct = _parse_json(json.dumps(ast.parse(src), cls=AstEncoder))
        self.assertEqual(cached, direct)

    def test_encode_node_matches_ast_encoder_for_single_node(self):
        """encode_node() must produce the same output as json.dumps(..., cls=AstEncoder)."""
        src = "def foo(x: int) -> str: return str(x)\n"
        tree = ast.parse(src)
        node = tree.body[0]
        via_encode_node = json.loads(encode_node(node))
        via_encoder = json.loads(json.dumps(node, cls=AstEncoder))
        self.assertEqual(via_encode_node, via_encoder)

    # ── Large file smoke test ─────────────────────────────────────────────

    def test_large_file_smoke(self):
        """Cache must handle files with many top-level functions without error."""
        src = "\n".join(f"def func_{i}(x): return x + {i}" for i in range(200))
        p = self._write("large.py", src)
        cache = _make_cache(self.tmp)

        ast_json = cache.get_ast_json(p, src)
        parsed = _parse_json(ast_json)
        self.assertEqual(parsed["node_type"], "Module")
        self.assertEqual(len(parsed["children"]["body"]), 200)

    # ── Singleton ─────────────────────────────────────────────────────────

    def test_singleton_same_instance(self):
        _reset_cache_singleton()
        c1 = get_cache()
        c2 = get_cache()
        self.assertIs(c1, c2)
        _reset_cache_singleton()

    def test_singleton_reset_yields_new_instance(self):
        _reset_cache_singleton()
        c1 = get_cache()
        _reset_cache_singleton()
        c2 = get_cache()
        self.assertIsNot(c1, c2)
        _reset_cache_singleton()

    # ── Frozen dataclass safety ───────────────────────────────────────────

    def test_file_cache_entry_is_immutable(self):
        """FileCacheEntry must be frozen so callers cannot mutate shared state."""
        import dataclasses
        self.assertTrue(dataclasses.fields(FileCacheEntry))
        entry = FileCacheEntry(
            file_path="/x",
            file_hash="abc",
            mtime=1.0,
            full_ast_json_z=b"",
            chunks={},
        )
        with self.assertRaises((dataclasses.FrozenInstanceError, AttributeError)):
            entry.mtime = 2.0  # type: ignore[misc]

    def test_ast_chunk_is_immutable(self):
        import dataclasses
        chunk = AstChunk(
            chunk_id="FunctionDef:foo",
            start_line=1,
            end_line=3,
            content_hash="abc",
            ast_json_z=b"",
        )
        with self.assertRaises((dataclasses.FrozenInstanceError, AttributeError)):
            chunk.start_line = 99  # type: ignore[misc]

    # ── CACHE_VERSION stored in disk file ─────────────────────────────────

    def test_cache_version_stored_in_disk_file(self):
        cache = _make_cache(self.tmp)
        p = self._write("ver.py", "x = 1\n")
        cache.get_ast_json(p, "x = 1\n")

        disk_p = cache._disk_path(p)
        assert disk_p is not None
        data = json.loads(disk_p.read_text(encoding="utf-8"))
        self.assertEqual(data["version"], CACHE_VERSION)


if __name__ == "__main__":
    unittest.main()
