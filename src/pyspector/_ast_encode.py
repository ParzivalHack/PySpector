"""
Shared AST → JSON encoder for PySpector.

Single source of truth for the JSON schema consumed by the Rust core.
Imported by both ast_cache.py and cli.py to eliminate encoder drift.
"""
from __future__ import annotations

import ast
import json
from typing import Any, Dict


class AstEncoder(json.JSONEncoder):
    """Serialize ast.AST nodes to the JSON schema expected by the Rust core."""

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
