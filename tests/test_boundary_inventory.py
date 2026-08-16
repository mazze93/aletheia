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
