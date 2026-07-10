"""
Git history and staged-content helpers for PySpector secret detection.

Scanning the working tree alone misses secrets that were committed and later
"removed" (they still live in the object database). `iter_all_blobs` walks
every blob reachable from any ref, scanning each unique blob's content
exactly once regardless of how many commits/paths reference it, using a
single `git rev-list` + two `git cat-file` batch calls rather than one
subprocess per blob or per commit.
"""

import subprocess
from pathlib import Path
from typing import Dict, Iterator, List, Tuple

MAX_BLOB_SIZE = 5 * 1024 * 1024  # 5MB - skip anything larger (unlikely to be a secret file)


def _run_git(args: List[str], cwd: Path, input_bytes: bytes = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(cwd), *args],
        input=input_bytes,
        capture_output=True,
        check=True,
    )


def _looks_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def iter_all_blobs(repo_path: Path) -> Iterator[Tuple[str, str]]:
    """
    Yields (path, text_content) for every blob reachable from any ref in the
    repository's history, each scanned exactly once regardless of how many
    commits reference identical content. Binary and oversized blobs are
    skipped. Yields nothing if `repo_path` is not a git repository or `git`
    is unavailable.
    """
    try:
        rev_list = _run_git(["rev-list", "--objects", "--all"], repo_path)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return

    blob_paths: Dict[str, str] = {}
    for line in rev_list.stdout.decode("utf-8", "replace").splitlines():
        if not line:
            continue
        sha, _, path = line.partition(" ")
        if path and sha not in blob_paths:
            blob_paths[sha] = path

    if not blob_paths:
        return

    shas = list(blob_paths.keys())

    try:
        check_result = _run_git(
            ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
            repo_path,
            input_bytes=("\n".join(shas) + "\n").encode("utf-8"),
        )
    except subprocess.CalledProcessError:
        return

    blob_shas: List[str] = []
    for line in check_result.stdout.decode("utf-8", "replace").splitlines():
        parts = line.split(" ")
        if len(parts) != 3:
            continue
        sha, obj_type, size_str = parts
        if obj_type == "blob" and size_str.isdigit() and int(size_str) <= MAX_BLOB_SIZE:
            blob_shas.append(sha)

    if not blob_shas:
        return

    try:
        batch_result = _run_git(
            ["cat-file", "--batch"],
            repo_path,
            input_bytes=("\n".join(blob_shas) + "\n").encode("utf-8"),
        )
    except subprocess.CalledProcessError:
        return

    data = batch_result.stdout
    pos = 0
    while pos < len(data):
        newline_idx = data.find(b"\n", pos)
        if newline_idx == -1:
            break

        header = data[pos:newline_idx].decode("utf-8", "replace")
        pos = newline_idx + 1

        parts = header.split(" ")
        if len(parts) != 3 or not parts[2].isdigit():
            continue

        sha, obj_type, size_str = parts
        size = int(size_str)
        content_bytes = data[pos : pos + size]
        pos += size + 1  # skip the record's trailing newline

        if obj_type != "blob" or _looks_binary(content_bytes):
            continue

        path = blob_paths.get(sha)
        if not path:
            continue

        yield path, content_bytes.decode("utf-8", "replace")


def iter_staged_files(repo_path: Path) -> Iterator[Tuple[str, str]]:
    """
    Yields (path, text_content) for the staged (index) version of each
    added/copied/modified file, used by the pre-commit hook to scan exactly
    what is about to be committed rather than the working-tree copy.
    """
    try:
        result = _run_git(
            ["diff", "--cached", "--name-only", "--diff-filter=ACM"],
            repo_path,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return

    paths = [p for p in result.stdout.decode("utf-8", "replace").splitlines() if p]

    for path in paths:
        try:
            show_result = _run_git(["show", f":{path}"], repo_path)
        except subprocess.CalledProcessError:
            continue

        content_bytes = show_result.stdout
        if _looks_binary(content_bytes):
            continue

        yield path, content_bytes.decode("utf-8", "replace")
