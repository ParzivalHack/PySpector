"""
Shared AST → JSON encoder for PySpector.

Single source of truth for the JSON schema consumed by the Rust core.
Imported by both ast_cache.py and cli.py to eliminate encoder drift.
"""
from __future__ import annotations

import ast
import json
import warnings
from typing import Any, Dict, Optional, Tuple, Union


class AstEncoder(json.JSONEncoder):
    """Serialize ast.AST nodes to the JSON schema expected by the Rust core.

    ``expr_context`` nodes (``Load`` / ``Store`` / ``Del``, the ``ctx`` field of Name,
    Attribute, Subscript, ...) are deliberately not emitted: nothing in the Rust core or in the
    rule files reads them, and they added one extra JSON object per identifier (~24% of the
    payload and ~20% of the encoding time on a large corpus).
    """

    def default(self, node: Any) -> Any:
        if isinstance(node, ast.AST):
            out: Dict[str, Any] = {
                "node_type": node.__class__.__name__,
                "lineno": getattr(node, "lineno", -1),
                "col_offset": getattr(node, "col_offset", -1),
            }
            child_nodes: Dict[str, Any] = {}
            simple_fields: Dict[str, Any] = {}
            for fname, value in ast.iter_fields(node):
                if type(value) is list:
                    if value and all(isinstance(n, ast.AST) for n in value):
                        child_nodes[fname] = value
                    else:
                        simple_fields[fname] = str(value) if value else []
                elif isinstance(value, ast.AST):
                    if isinstance(value, ast.expr_context):
                        continue
                    child_nodes[fname] = [value]
                else:
                    if isinstance(value, bytes):
                        simple_fields[fname] = value.decode("utf-8", errors="replace")
                    elif isinstance(value, int) and value.bit_length() > 14000:
                        simple_fields[fname] = 0
                    elif isinstance(value, (int, float, str, bool)) or value is None:
                        simple_fields[fname] = value
                    else:
                        simple_fields[fname] = str(value)
            out["children"] = child_nodes
            out["fields"] = simple_fields
            return out
        if isinstance(node, bytes):
            return node.decode("utf-8", errors="replace")
        if hasattr(node, "__dict__"):
            return str(node)
        return super().default(node)


def encode_node(node: ast.AST) -> str:
    """Serialize a single AST node to JSON."""
    return json.dumps(node, cls=AstEncoder)


# ── Parse + encode as one unit of work ───────────────────────────────────────

# What went wrong with one file: (kind, message, line number). `kind` is one of
# "warning", "syntax", "unicode" or "error". Plain strings and ints, so it is cheap to send
# back from a worker process and the caller can render it exactly like a raised exception.
Problem = Tuple[str, str, Optional[int]]


def describe_problem(exc: BaseException) -> Problem:
    """Reduce an exception raised while reading/parsing a file to a `Problem`."""
    if isinstance(exc, SyntaxWarning):
        return ("warning", getattr(exc, "msg", None) or str(exc), getattr(exc, "lineno", None))
    if isinstance(exc, SyntaxError):
        return ("syntax", exc.msg, exc.lineno)
    if isinstance(exc, UnicodeDecodeError):
        return ("unicode", exc.reason, None)
    return ("error", str(exc), None)


def parse_and_encode(path: str, content: str, warnings_as_errors: bool = False) -> str:
    """``ast.parse`` + JSON encoding, the CPU-bound work done for every file without a cache hit.

    With *warnings_as_errors*, a SyntaxWarning makes the parse fail (the file is then reported
    and left out of the scan); otherwise SyntaxWarnings are ignored.
    """
    with warnings.catch_warnings():
        warnings.filterwarnings("error" if warnings_as_errors else "ignore", category=SyntaxWarning)
        tree = ast.parse(content, filename=path)
    return json.dumps(tree, cls=AstEncoder)


def parse_and_encode_task(task: Tuple[str, str, bool]) -> Union[str, Problem]:
    """Worker entry point: returns the AST JSON, or a `Problem`. Never raises, so one bad file
    cannot abort a whole batch (or a worker process)."""
    path, content, warnings_as_errors = task
    try:
        return parse_and_encode(path, content, warnings_as_errors)
    except Exception as e:  # every failure is reported per file, never raised
        return describe_problem(e)
