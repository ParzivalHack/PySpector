"""Tests for A_SINK rules — all triggered by taint engine, verified without FPs."""

import os, sys, tempfile, textwrap, warnings
from pathlib import Path
import pytest


def _wrap(code):
    ind = "\n".join("    " + l for l in textwrap.dedent(code).splitlines())
    return f"def _view(request):\n{ind}\n"


def run(code, filename="app.py"):
    from pyspector._rust_core import run_scan
    from pyspector.config import get_default_rules
    import ast as _ast, json as _json
    from pyspector.cli import AstEncoder
    wrapped = _wrap(code)
    rules = get_default_rules()
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, filename)
        Path(p).write_text(wrapped)
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore")
            try: aj = _json.dumps(_ast.parse(wrapped), cls=AstEncoder)
            except: aj = "{}"
        files = [{"file_path": filename, "content": wrapped, "ast_json": aj}]
        return [{"rule_id": r.rule_id} for r in run_scan(d, rules, {"exclude": []}, files)]


def fires(code, rule_id): return [f for f in run(code) if f["rule_id"] == rule_id]
def not_fires(code, rule_id): return not fires(code, rule_id)


# --- HASATTR837 ---
class TestHasattr837:
    def test_tainted_silent_disabled(self):
        # HASATTR837 disabled: hasattr() returns bool — not a security sink,
        # generates FPs on stdlib code that uses hasattr for duck-typing checks.
        assert not_fires("attr=request.GET.get('f'); hasattr(obj,attr)", "HASATTR837")
    def test_constant_safe(self):
        assert not_fires("hasattr(obj,'is_active')", "HASATTR837")

# --- VARS840 ---
class TestVars840:
    def test_tainted_silent_disabled(self):
        # VARS840 disabled: vars() returns __dict__ — information disclosure but
        # low security impact; generates FPs in code using vars() for introspection.
        assert not_fires("o=request.GET.get('obj'); vars(o)", "VARS840")
    def test_constant_safe(self):
        assert not_fires("vars(MyClass())", "VARS840")

# --- DIR849 ---
class TestDir849:
    def test_tainted_silent_disabled(self):
        # DIR849 disabled: dir() lists attributes for introspection — not a security
        # sink; generates FPs in code that uses dir() for reflection/debugging.
        assert not_fires("o=request.GET.get('obj'); dir(o)", "DIR849")
    def test_constant_safe(self):
        assert not_fires("dir(str)", "DIR849")

# --- CALLABLE1131 ---
class TestCallable1131:
    def test_tainted_silent_disabled(self):
        # CALLABLE1131 disabled: callable() checks if object is callable —
        # not a security sink; generates FPs from deep inter-procedural taint.
        assert not_fires("o=request.GET.get('fn'); callable(o)", "CALLABLE1131")
    def test_constant_safe(self):
        assert not_fires("callable(print)", "CALLABLE1131")

# --- BYTES1005 ---
class TestBytes1005:
    def test_tainted_silent_disabled(self):
        # BYTES1005 disabled: bytes() encoding is not a security sink on its own.
        assert not_fires("d=request.GET.get('data'); bytes(d,'utf-8')", "BYTES1005")
    def test_constant_safe(self):
        assert not_fires("bytes('hello','utf-8')", "BYTES1005")

# --- BYTEARRAY1008 ---
class TestBytearray1008:
    def test_tainted_silent_disabled(self):
        # BYTEARRAY1008 disabled: bytearray() creates a mutable buffer — not a
        # security sink; generates FPs in asyncio/networking code that buffers I/O.
        assert not_fires("d=request.GET.get('data'); bytearray(d,'utf-8')", "BYTEARRAY1008")
    def test_constant_safe(self):
        assert not_fires("bytearray(b'hello')", "BYTEARRAY1008")

# --- MEMORYVIEW1011 ---
class TestMemoryview1011:
    def test_tainted_silent_disabled(self):
        # MEMORYVIEW1011 disabled: memory view creation is not a security sink.
        assert not_fires("d=request.GET.get('data'); b=bytes(d,'utf-8'); memoryview(b)", "MEMORYVIEW1011")
    def test_constant_safe(self):
        assert not_fires("memoryview(b'hello')", "MEMORYVIEW1011")

# --- ORD1014 ---
class TestOrd1014:
    def test_tainted_silent_disabled(self):
        # ORD1014 disabled: ord() returns the integer code point of a character —
        # never a security sink; generates FPs in encoding/codec implementations.
        assert not_fires("c=request.GET.get('char'); ord(c)", "ORD1014")
    def test_constant_safe(self):
        assert not_fires("ord('A')", "ORD1014")

# --- CHR1017 ---
class TestChr1017:
    def test_tainted_silent_disabled(self):
        # CHR1017 disabled: chr() converts an integer to a character —
        # never a security sink; generates FPs in encoding implementations.
        assert not_fires("n=request.GET.get('n'); chr(n)", "CHR1017")
    def test_constant_safe(self):
        assert not_fires("chr(65)", "CHR1017")

# --- CENTER927 / LJUST930 / RJUST933 ---
class TestJustification:
    def test_center_silent_disabled(self):
        # CENTER927 disabled: string centering is a cosmetic operation — not a sink.
        assert not_fires("w=request.GET.get('w'); 'x'.center(w)", "CENTER927")
    def test_center_constant_safe(self):
        assert not_fires("'x'.center(80)", "CENTER927")
    def test_ljust_silent_disabled(self):
        # LJUST930 disabled: string left-justification is not a security sink.
        assert not_fires("w=request.GET.get('w'); 'x'.ljust(w)", "LJUST930")
    def test_rjust_silent_disabled(self):
        # RJUST933 disabled: zero findings across all scanned repos.
        assert not_fires("w=request.GET.get('w'); 'x'.rjust(w)", "RJUST933")

# --- RANGE1056 ---
class TestRange1056:
    def test_tainted_silent_disabled(self):
        # RANGE1056 disabled: range() iteration bound is not a security sink.
        assert not_fires("n=request.GET.get('n'); range(n)", "RANGE1056")
    def test_constant_safe(self):
        assert not_fires("range(100)", "RANGE1056")

# --- JOIN876 ---
class TestJoin876:
    def test_tainted_parts_silent_disabled(self):
        # JOIN876 disabled: .join() with tainted data generates FPs from deep
        # inter-proc taint reaching error messages and SQL placeholder construction.
        assert not_fires("parts=request.GET.getlist('p'); '/'.join(parts)", "JOIN876")
    def test_constant_safe(self):
        assert not_fires("'/'.join(['a','b','c'])", "JOIN876")

# --- SORTED1074 ---
class TestSorted1074:
    def test_tainted_silent_disabled(self):
        # SORTED1074 disabled: sorting user data is not a security sink.
        assert not_fires("data=request.GET.getlist('items'); sorted(data)", "SORTED1074")
    def test_constant_safe(self):
        assert not_fires("sorted([3,1,2])", "SORTED1074")

# --- SUM1080 ---
class TestSum1080:
    def test_tainted_silent_disabled(self):
        # SUM1080 disabled: summing user data is not a security sink.
        assert not_fires("vals=request.GET.getlist('v'); sum(vals)", "SUM1080")
    def test_constant_safe(self):
        assert not_fires("sum([1,2,3])", "SUM1080")

# --- SET1047 ---
class TestSet1047:
    def test_tainted_silent_disabled(self):
        # SET1047 disabled: set() deduplication causes FPs from deep inter-proc taint.
        assert not_fires("items=request.GET.getlist('i'); set(items)", "SET1047")
    def test_constant_safe(self):
        assert not_fires("set([1,2,3])", "SET1047")
