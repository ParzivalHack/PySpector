"""
Incremental AST cache for PySpector.

Three-level hierarchy
---------------------
L1  in-memory   mtime guard — zero work on hit within a process run
L2  disk        content-hash guard — no parse/encode across runs
L3  chunk-aware per-function/class subtree reuse when a file partially changes

Bottleneck eliminated: json.dumps(ast_tree, cls=AstEncoder) is pure-Python
O(N nodes). ast.parse() is C and negligible by comparison.

Persistence format
------------------
Entries are stored as JSON with zlib-compressed fields base64-encoded.
pickle is deliberately NOT used: it executes arbitrary code on load, making
it unsafe when cache files reside in a repository directory controlled by
an untrusted third party.
"""
from __future__ import annotations

import ast
import base64
import dataclasses
import hashlib
import json
import warnings
import zlib
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ._ast_encode import AstEncoder, encode_node  # noqa: F401  (re-exported for tests)

# v1 used pickle (security risk); v2 uses JSON + base64
CACHE_VERSION = 2
_ZLIB_LEVEL = 3          # favour speed over ratio for ephemeral cache data
MAX_L1_ENTRIES: int = 512


# ── Data structures ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AstChunk:
    """Serialised AST for one top-level syntactic block."""
    chunk_id: str       # "FunctionDef:my_func", "ClassDef:MyClass", "stmt:42"
    start_line: int     # 1-based, matches ast.lineno
    end_line: int
    content_hash: str   # sha256 of this chunk's source text
    ast_json_z: bytes   # zlib-compressed JSON of the AstNode subtree


@dataclass(frozen=True)
class FileCacheEntry:
    file_path: str
    file_hash: str           # sha256 of full file content
    mtime: float
    full_ast_json_z: bytes   # zlib-compressed full AST JSON string
    chunks: Dict[str, AstChunk]
    version: int = CACHE_VERSION


# ── Chunking helpers ─────────────────────────────────────────────────────────

_NAMED_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _make_chunk_id(node: ast.stmt, seen: Dict[str, int]) -> str:
    """Produce a stable chunk ID for a top-level AST statement."""
    if isinstance(node, _NAMED_TYPES):
        base = f"{node.__class__.__name__}:{node.name}"
        idx = seen.get(base, 0)
        seen[base] = idx + 1
        return base if idx == 0 else f"{base}:{idx}"
    return f"stmt:{node.lineno}"


def _source_slice(lines: List[str], node: ast.stmt) -> str:
    start = node.lineno - 1  # ast.lineno is 1-based
    end = getattr(node, "end_lineno", node.lineno)
    return "".join(lines[start:end])


# ── Module JSON assembly ─────────────────────────────────────────────────────


def _assemble_module_json(
    body_parts: List[str],
    type_ignore_parts: List[str],
) -> str:
    """
    Build the Module JSON wrapper around pre-serialized body/type_ignore fragments.

    Pre-conditions (caller must ensure):
      Every string in body_parts / type_ignore_parts is valid JSON produced by
      encode_node(). Values are embedded verbatim — not re-serialized or escaped.

    Mirrors AstEncoder's field/children split:
      - non-empty AST-node list → placed under "children"
      - empty list             → placed under "fields" as []
    """
    ch_items: List[str] = []
    fi_items: List[str] = []

    if body_parts:
        ch_items.append('"body": [' + ",".join(body_parts) + "]")
    else:
        fi_items.append('"body": []')

    if type_ignore_parts:
        ch_items.append('"type_ignores": [' + ",".join(type_ignore_parts) + "]")
    else:
        fi_items.append('"type_ignores": []')

    ch_json = "{" + ", ".join(ch_items) + "}"
    fi_json = "{" + ", ".join(fi_items) + "}"
    return (
        '{"node_type": "Module", "lineno": -1, "col_offset": -1, '
        '"children": ' + ch_json + ', '
        '"fields": ' + fi_json + "}"
    )


# ── Incremental JSON construction ────────────────────────────────────────────


def _build_ast_json_and_chunks(
    tree: ast.Module,
    source: str,
    old_chunks: Dict[str, AstChunk],
) -> Tuple[str, Dict[str, AstChunk]]:
    """
    Serialise *tree* to AST JSON, reusing encoded subtrees from *old_chunks*
    for any chunk whose content hash AND start_line are both unchanged.

    Skips encode_node() for every unchanged top-level function/class —
    typically 80-100 % of body nodes when only a few lines change.

    Returns (full_ast_json, new_chunks_dict).
    """
    lines = source.splitlines(keepends=True)
    seen: Dict[str, int] = {}
    new_chunks: Dict[str, AstChunk] = {}
    body_parts: List[str] = []

    for node in tree.body:
        cid = _make_chunk_id(node, seen)
        src = _source_slice(lines, node)
        end = getattr(node, "end_lineno", node.lineno)
        new_hash = hashlib.sha256(src.encode()).hexdigest()

        old = old_chunks.get(cid)
        reuse = (
            old is not None
            and old.content_hash == new_hash
            and old.start_line == node.lineno
        )

        if reuse:
            assert old is not None  # type narrowing
            node_json = zlib.decompress(old.ast_json_z).decode()
            chunk_z = old.ast_json_z
        else:
            node_json = encode_node(node)
            chunk_z = zlib.compress(node_json.encode(), _ZLIB_LEVEL)

        new_chunks[cid] = AstChunk(
            chunk_id=cid,
            start_line=node.lineno,
            end_line=end,
            content_hash=new_hash,
            ast_json_z=chunk_z,
        )
        body_parts.append(node_json)

    type_ignore_parts = [encode_node(ti) for ti in tree.type_ignores]
    full_json = _assemble_module_json(body_parts, type_ignore_parts)
    return full_json, new_chunks


# ── Disk serialization — JSON + base64, no executable deserialization ─────────


def _serialize_entry(entry: FileCacheEntry) -> str:
    """Serialize a FileCacheEntry to a JSON string. No code-execution paths."""
    return json.dumps({
        "version": entry.version,
        "file_path": entry.file_path,
        "file_hash": entry.file_hash,
        "mtime": entry.mtime,
        "full_ast_json_z": base64.b64encode(entry.full_ast_json_z).decode(),
        "chunks": {
            k: {
                "chunk_id": c.chunk_id,
                "start_line": c.start_line,
                "end_line": c.end_line,
                "content_hash": c.content_hash,
                "ast_json_z": base64.b64encode(c.ast_json_z).decode(),
            }
            for k, c in entry.chunks.items()
        },
    })


def _deserialize_entry(raw: str) -> FileCacheEntry:
    """Deserialize a FileCacheEntry from JSON. Raises on malformed data."""
    d = json.loads(raw)
    return FileCacheEntry(
        file_path=d["file_path"],
        file_hash=d["file_hash"],
        mtime=float(d["mtime"]),
        full_ast_json_z=base64.b64decode(d["full_ast_json_z"]),
        chunks={
            k: AstChunk(
                chunk_id=v["chunk_id"],
                start_line=int(v["start_line"]),
                end_line=int(v["end_line"]),
                content_hash=v["content_hash"],
                ast_json_z=base64.b64decode(v["ast_json_z"]),
            )
            for k, v in d["chunks"].items()
        },
        version=int(d["version"]),
    )


# ── Cache ─────────────────────────────────────────────────────────────────────


class IncrementalAstCache:
    """
    Three-level incremental AST cache.

    Parameters
    ----------
    cache_dir : Path, optional
        Directory for the persistent (L2) disk cache.  When *None* only the
        in-memory (L1) cache is active.  If the directory cannot be created,
        a warning is issued and the cache operates in L1-only mode.
    max_l1_entries : int
        Maximum entries kept in the in-memory LRU cache.  Oldest entries are
        evicted when the limit is exceeded.  Default: 512.

    Usage
    -----
    ::

        cache = IncrementalAstCache(cache_dir=Path(".pyspector_cache/ast"))
        ast_json = cache.get_ast_json(Path("src/foo.py"), content)
    """

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        max_l1_entries: int = MAX_L1_ENTRIES,
    ) -> None:
        self._l1: OrderedDict[str, FileCacheEntry] = OrderedDict()
        self._max_l1 = max_l1_entries
        self._cache_dir: Optional[Path] = None
        if cache_dir:
            try:
                cache_dir.mkdir(parents=True, exist_ok=True)
                self._cache_dir = cache_dir
            except OSError as e:
                warnings.warn(
                    f"PySpector: cannot create cache directory {cache_dir!r}: {e}. "
                    "Disk cache disabled for this run.",
                    stacklevel=2,
                )

    # ── Public API ───────────────────────────────────────────────────────────

    def get_ast_json(self, file_path: Path, content: str) -> str:
        """
        Return the AST JSON string for *file_path*.

        Raises
        ------
        SyntaxError
            If the file cannot be parsed, so callers can emit user-facing
            warnings while keeping cache logic out of the CLI layer.
        """
        return zlib.decompress(self._get_entry(file_path, content).full_ast_json_z).decode()

    def invalidate(self, file_path: Path) -> None:
        """Remove all cached data for a single file."""
        key = str(file_path.resolve())
        self._l1.pop(key, None)
        p = self._disk_path(file_path)
        if p and p.exists():
            p.unlink(missing_ok=True)

    def get_changed_chunks(
        self, file_path: Path, old_content: str, new_content: str
    ) -> List[str]:
        """
        Return the IDs of top-level chunks that differ between two versions
        of a file, without updating the cache.  Useful for incremental
        analysis drivers that want to know exactly what changed.
        """
        def _chunk_hashes(source: str) -> Dict[str, str]:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=SyntaxWarning)
                try:
                    tree = ast.parse(source, filename=str(file_path))
                except SyntaxError:
                    return {}
            lines = source.splitlines(keepends=True)
            seen: Dict[str, int] = {}
            out: Dict[str, str] = {}
            for node in tree.body:
                cid = _make_chunk_id(node, seen)
                out[cid] = hashlib.sha256(_source_slice(lines, node).encode()).hexdigest()
            return out

        old_h = _chunk_hashes(old_content)
        new_h = _chunk_hashes(new_content)
        changed = [cid for cid, h in new_h.items() if old_h.get(cid) != h]
        changed += [cid for cid in old_h if cid not in new_h]
        return changed

    # ── Internal ─────────────────────────────────────────────────────────────

    def _l1_get(self, key: str) -> Optional[FileCacheEntry]:
        entry = self._l1.get(key)
        if entry is not None:
            self._l1.move_to_end(key)
        return entry

    def _l1_put(self, key: str, entry: FileCacheEntry) -> None:
        self._l1[key] = entry
        self._l1.move_to_end(key)
        while len(self._l1) > self._max_l1:
            self._l1.popitem(last=False)  # evict least-recently-used

    def _get_entry(self, file_path: Path, content: str) -> FileCacheEntry:
        # Resolve once: L1 key and L2 hash must both use the canonical path.
        file_path = file_path.resolve()
        key = str(file_path)

        try:
            mtime = file_path.stat().st_mtime
        except OSError:
            mtime = 0.0

        # L1 – mtime guard (cheapest check: dict lookup + float compare)
        l1 = self._l1_get(key)
        if l1 and l1.mtime == mtime and l1.version == CACHE_VERSION:
            return l1

        file_hash = hashlib.sha256(content.encode()).hexdigest()

        # L1 – hash guard (file touched externally but content unchanged)
        if l1 and l1.file_hash == file_hash and l1.version == CACHE_VERSION:
            updated = dataclasses.replace(l1, mtime=mtime)
            self._l1_put(key, updated)
            return updated

        # L2 – disk (survive across process restarts)
        l2 = self._disk_load(file_path, file_hash)
        if l2:
            updated_l2 = dataclasses.replace(l2, mtime=mtime)
            self._l1_put(key, updated_l2)
            return updated_l2

        # L3 – build with chunk-level subtree reuse
        old_chunks: Dict[str, AstChunk] = (
            l1.chunks if (l1 and l1.version == CACHE_VERSION) else {}
        )
        entry = self._build(file_path, content, file_hash, mtime, old_chunks)
        self._l1_put(key, entry)
        self._disk_save(entry)
        return entry

    def _build(
        self,
        file_path: Path,
        content: str,
        file_hash: str,
        mtime: float,
        old_chunks: Dict[str, AstChunk],
    ) -> FileCacheEntry:
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=SyntaxWarning)
            tree = ast.parse(content, filename=str(file_path))  # SyntaxError propagates

        full_json, chunks = _build_ast_json_and_chunks(tree, content, old_chunks)
        return FileCacheEntry(
            file_path=str(file_path),
            file_hash=file_hash,
            mtime=mtime,
            full_ast_json_z=zlib.compress(full_json.encode(), _ZLIB_LEVEL),
            chunks=chunks,
        )

    # ── Disk I/O ─────────────────────────────────────────────────────────────

    def _disk_path(self, file_path: Path) -> Optional[Path]:
        if not self._cache_dir:
            return None
        key = hashlib.sha256(str(file_path.resolve()).encode()).hexdigest()
        return self._cache_dir / f"{key}.json"

    def _disk_load(self, file_path: Path, file_hash: str) -> Optional[FileCacheEntry]:
        p = self._disk_path(file_path)
        if not p or not p.exists():
            return None
        try:
            entry = _deserialize_entry(p.read_text(encoding="utf-8"))
            if entry.version == CACHE_VERSION and entry.file_hash == file_hash:
                return entry
        except Exception:
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass
        return None

    def _disk_save(self, entry: FileCacheEntry) -> None:
        p = self._disk_path(Path(entry.file_path))
        if not p:
            return
        tmp = p.with_suffix(".tmp")
        try:
            tmp.write_text(_serialize_entry(entry), encoding="utf-8")
            tmp.replace(p)  # atomic on POSIX; best-effort on Windows
        except OSError as e:
            warnings.warn(
                f"PySpector: cache write failed for {entry.file_path!r}: {e}",
                stacklevel=2,
            )
        except Exception as e:
            warnings.warn(
                f"PySpector: unexpected cache error for {entry.file_path!r}: {e}",
                stacklevel=2,
            )
        finally:
            # Remove temp file if replace() did not atomically rename it.
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass


# ── Process-level singleton ───────────────────────────────────────────────────

_instance: Optional[IncrementalAstCache] = None


def get_cache(scan_path: Optional[Path] = None) -> IncrementalAstCache:
    """
    Return the process-level cache instance.

    The disk cache is rooted at *<scan_path>/.pyspector_cache/ast* when
    *scan_path* is supplied on the first call.  Subsequent calls return the
    same instance regardless of *scan_path*.
    """
    global _instance
    if _instance is None:
        cache_dir: Optional[Path] = None
        if scan_path:
            base = scan_path if scan_path.is_dir() else scan_path.parent
            cache_dir = base / ".pyspector_cache" / "ast"
        _instance = IncrementalAstCache(cache_dir=cache_dir)
    return _instance


def _reset_cache_singleton() -> None:
    """Reset the process-level singleton. Use only in tests."""
    global _instance
    _instance = None
