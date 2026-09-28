"""Every dialect-dependent construct is inventoried and tagged, or absent.

The fix for issue #3 replaced `\\b` with an explicit policy. Nothing stops the
next pattern from being written with `\\b` again — the class would reopen
quietly, and the parity corpus would only catch it if someone happened to add a
vector for that exact token.

So this test reads both implementations and refuses constructs whose meaning
depends on the runtime's idea of a word, unless the occurrence is on the
allowlist below with a stated reason. Adding a pattern with `\\b` fails the
build; adding it to the allowlist requires writing down why it is safe.

Covers the closure-gate line: *every `\\b`, `\\B`, `\\w`, `\\W`, `[A-Za-z]` and
boundary lookaround is inventoried and tagged as safe, replaced, or
intentionally scoped.*
"""
from __future__ import annotations

import ast
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PY_ASSESS = ROOT / "src" / "aletheia" / "assess.py"
TS_ASSESS = ROOT / "typescript" / "src" / "assess.ts"

# Constructs whose meaning differs between Python's `re` and ECMAScript.
FORBIDDEN = {
    r"\b": "word boundary — dialect-dependent; use bounded() from boundary.py",
    r"\B": "negated word boundary — same problem as \\b",
}

# `\w` / `\W` are allowed only where the Unicode-aware reading is intended AND
# the port uses an explicitly equivalent class. Each entry states the pairing.
ALLOWED_WORD_CLASS = {
    r"[a-z][\w-]*@\d+[\d.]*": (
        "pkg@version. Unicode-aware on purpose so café@1.2.3 is one token; the "
        "port uses [\\p{L}\\p{N}_-] to say the same thing explicitly."
    ),
}


def code_without_docstring(path: pathlib.Path) -> str:
    """Strip the module docstring and comments.

    They discuss `\\b` at length — necessarily, since explaining the fix means
    naming the thing being fixed — and a scanner that cannot tell prose from
    code would make the documentation unwritable.
    """
    text = path.read_text(encoding="utf-8")

    # Module docstring (Python) or leading block comment (TS).
    text = re.sub(r'^r?""".*?"""', "", text, count=1, flags=re.S)
    text = re.sub(r"^/\*\*.*?\*/", "", text, count=1, flags=re.S)

    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
            continue
        lines.append(line)
    return "\n".join(lines)


_BOUNDED_PY = {"bounded", "bounded_left"}
_IGNORECASE_ATTRS = {"I", "IGNORECASE"}


def case_insensitive_bounded_calls_py(source: str, name: str) -> list[str]:
    """`re.compile(bounded(...), <flags with re.I>)`, found per call via `ast`.

    Call-level, not line-level: a flag on the next line, a `flags=` keyword,
    a `re.M | re.I` union and an inline `(?i)` all count.
    """
    found = []
    for node in ast.walk(ast.parse(source)):
        if not (isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "compile"
                and node.args and isinstance(node.args[0], ast.Call)
                and getattr(node.args[0].func, "id", None) in _BOUNDED_PY):
            continue
        flag_nodes = list(node.args[1:]) + [k.value for k in node.keywords if k.arg == "flags"]
        has_flag = any(
            isinstance(sub, ast.Attribute) and sub.attr in _IGNORECASE_ATTRS
            for flag in flag_nodes for sub in ast.walk(flag)
        )
        inner = node.args[0].args
        has_inline = bool(inner) and isinstance(inner[0], ast.Constant) \
            and isinstance(inner[0].value, str) and re.search(r"\(\?[a-zA-Z]*i", inner[0].value)
        if has_flag or has_inline:
            found.append(f"{name}:{node.lineno}: {ast.unparse(node)[:100]}")
    return found


def _call_extent(text: str, open_paren: int) -> int:
    """Index just past the `)` matching `open_paren`, skipping string literals."""
    depth, i = 0, open_paren
    while i < len(text):
        ch = text[i]
        if ch in "'\"`":
            i = text.index(ch, i + 1) + 1  # patterns here never escape their quote
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise ValueError("unbalanced call")


def case_insensitive_bounded_calls_ts(source: str, name: str) -> list[str]:
    """`new RegExp(bounded(...), '<flags with i>')`, found per call, across lines."""
    found = []
    for m in re.finditer(r"new RegExp\(", source):
        call = source[m.start():_call_extent(source, m.end() - 1)]
        if not re.match(r"new RegExp\(\s*bounded(?:Left)?\(", call):
            continue
        flags = re.search(r"""['"]([a-z]*)['"]\s*,?\s*\)$""", call)
        if flags and "i" in flags.group(1):
            line = source.count("\n", 0, m.start()) + 1
            found.append(f"{name}:{line}: {' '.join(call.split())[:100]}")
    return found


class NoDialectDependentBoundaries(unittest.TestCase):
    def test_python_assessor_has_no_word_boundary_escapes(self):
        self._assert_clean(PY_ASSESS)

    def test_typescript_assessor_has_no_word_boundary_escapes(self):
        self._assert_clean(TS_ASSESS)

    def _assert_clean(self, path: pathlib.Path):
        code = code_without_docstring(path)
        found = []
        for construct, why in FORBIDDEN.items():
            for i, line in enumerate(code.splitlines(), 1):
                if construct in line:
                    found.append(f"{path.name}:{i}: {construct!r} — {why}\n    {line.strip()}")
        self.assertEqual(found, [], "\n".join(found))

    def test_no_bounded_pattern_is_compiled_case_insensitively(self):
        """The third primitive: a global ignore-case flag on a bounded pattern.

        `re.I` / ECMAScript `i` fold the boundary class along with the keyword,
        so `[A-Za-z0-9_]` accepts K (U+212A) and ſ (U+017F) — and in Python
        İ and ı — and a keyword beside one of them is suppressed. Case-
        insensitive keywords go through `bounded_caseless()` /
        `boundedCaseless()`, which fold the keyword and never the edge.
        """
        found = (
            case_insensitive_bounded_calls_py(PY_ASSESS.read_text(encoding="utf-8"), PY_ASSESS.name)
            + case_insensitive_bounded_calls_ts(TS_ASSESS.read_text(encoding="utf-8"), TS_ASSESS.name)
        )
        self.assertEqual(
            found, [],
            "Bounded pattern compiled case-insensitively — use bounded_caseless() / "
            "boundedCaseless() and drop the flag:\n" + "\n".join(found),
        )

    def test_the_gate_sees_calls_not_lines(self):
        """The gate itself, probed. A line scanner missed a flag on the next
        line; these are the shapes a real edit would take."""
        py_cases = {
            're.compile(bounded(r"x"), re.I)': True,
            're.compile(bounded(r"x"),\n           re.I)': True,
            're.compile(bounded(r"x"), flags=re.IGNORECASE)': True,
            're.compile(bounded_left(r"x"), re.M | re.I)': True,
            're.compile(bounded(r"(?i)x"))': True,
            're.compile(bounded_caseless(r"x"))': False,
            're.compile(bounded(r"x"), re.M)': False,
        }
        for src, expected in py_cases.items():
            self.assertEqual(bool(case_insensitive_bounded_calls_py(src, "t.py")), expected, src)
        ts_cases = {
            "new RegExp(bounded(String.raw`x`), 'giu')": True,
            "new RegExp(\n  bounded(String.raw`(?:a|b)`),\n  'giu',\n)": True,
            "new RegExp(boundedLeft(String.raw`x`), \"iu\")": True,
            "new RegExp(boundedCaseless(String.raw`x`), 'gu')": False,
            "new RegExp(bounded(String.raw`(?:i)`), 'gu')": False,
        }
        for src, expected in ts_cases.items():
            self.assertEqual(bool(case_insensitive_bounded_calls_ts(src, "t.ts")), expected, src)

    def test_word_class_uses_are_all_allowlisted(self):
        """`\\w` may appear, but only where the pairing is written down."""
        code = code_without_docstring(PY_ASSESS)
        unexplained = []
        for i, line in enumerate(code.splitlines(), 1):
            if r"\w" not in line and r"\W" not in line:
                continue
            if any(key in line for key in ALLOWED_WORD_CLASS):
                continue
            unexplained.append(f"{PY_ASSESS.name}:{i}: {line.strip()}")
        self.assertEqual(
            unexplained, [],
            "Unallowlisted \\w use — add it to ALLOWED_WORD_CLASS with the "
            "reason and the port's equivalent:\n" + "\n".join(unexplained),
        )


class BoundaryPolicyIsMirrored(unittest.TestCase):
    """The two boundary modules must state the same rule."""

    def test_ascii_identifier_alphabet_matches(self):
        py = (ROOT / "src" / "aletheia" / "boundary.py").read_text(encoding="utf-8")
        ts = (ROOT / "typescript" / "src" / "boundary.ts").read_text(encoding="utf-8")
        alphabet = "[A-Za-z0-9_]"
        self.assertIn(f'ASCII_IDENTIFIER_CHAR = "{alphabet}"', py)
        self.assertIn(f'ASCII_IDENTIFIER_CHAR = "{alphabet}"', ts)

    def test_both_define_left_and_right(self):
        for path in (ROOT / "src" / "aletheia" / "boundary.py",
                     ROOT / "typescript" / "src" / "boundary.ts"):
            text = path.read_text(encoding="utf-8")
            self.assertIn("(?<!", text, f"{path.name} lost its left edge")
            self.assertIn("(?!", text, f"{path.name} lost its right edge")


if __name__ == "__main__":
    unittest.main()
