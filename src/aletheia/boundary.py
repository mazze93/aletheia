r"""The lexical boundary policy, stated once.

`\b` is not a security boundary. It means "a transition between `\w` and `\W`",
and the two runtimes disagree about what `\w` is: Python's is Unicode-aware for
`str` patterns, JavaScript's is ASCII-only. Security semantics were therefore
resting on a regex dialect default, which is how `criticalé` came to score 0.0
in the oracle while the port matched it (issue #3).

Attempting to make two dialect defaults coincide is the wrong repair. The
policy has to be stated explicitly and then implemented in each language:

    Match a security keyword unless it is embedded inside a larger ASCII
    identifier. Unicode letters adjacent to it do not suppress a detection.

So `criticalé` matches (the `é` is not part of an ASCII identifier), while
`hypercritical` and `critical_path` do not (they are one larger identifier). An
attacker cannot hide a keyword by decorating it with non-ASCII characters, and
ordinary multilingual prose is not turned into a false positive.

This is deliberately narrower than "Unicode word boundary". It encodes what the
detector actually cares about — is this token standing on its own, or is it a
fragment of a longer ASCII word — rather than deferring to a general text
segmentation algorithm whose answer would still differ between runtimes.

**Where this policy does not apply.** Identifiers whose canonical grammar is
itself Unicode-aware — usernames, internationalized hostnames, registry-specific
package names — must not be matched with keyword regexes at all. Parse them with
the target grammar and compare canonical fields. Nothing here is a substitute
for that.

`typescript/src/boundary.ts` mirrors this file. `parity/compare.py` enforces the
mirror; `parity/boundary_inventory.py` enforces that every pattern in both
implementations is accounted for.
"""
from __future__ import annotations

# The alphabet of an ASCII identifier. Not `\w`: that is the dialect-dependent
# construct this module exists to stop relying on.
ASCII_IDENTIFIER_CHAR = "[A-Za-z0-9_]"

#: Left edge — the match may not be preceded by an ASCII identifier character.
LEFT = f"(?<!{ASCII_IDENTIFIER_CHAR})"

#: Right edge — the match may not be followed by an ASCII identifier character.
RIGHT = f"(?!{ASCII_IDENTIFIER_CHAR})"


# A non-whitespace character, agreed across runtimes.
#
# The second dialect disagreement, found by the 651-case mutation corpus and
# invisible to the 69 hand-written vectors: ECMAScript's WhiteSpace production
# includes U+FEFF (zero-width no-break space / BOM); Python's `\s` does not. So
# `\S+` captured `npm install foo﻿` in the oracle and `npm install foo` in
# the port — the same detection, a different *extent*.
#
# Extent matters here specifically. `governing_parameters` is the list a human
# is told to verify at a registry, and a trailing invisible character in that
# string is the kind of thing that makes a verification silently fail. Aligning
# to the narrower reading keeps the captured parameter to what is actually
# visible.
NOT_SPACE = r"[^\s﻿]"


# Case-insensitivity, stated as policy rather than inherited from a flag.
#
# The third dialect finding, and the first one inside the fix itself: compiling
# a bounded pattern with `re.I` (or ECMAScript `i`) case-folds the boundary
# class too. `[A-Za-z0-9_]` stops being ASCII — Python `re.I` lets U+0130,
# U+0131, U+017F and U+212A satisfy it; ECMAScript `iu` lets U+017F and U+212A.
# A keyword beside one of those letters then reads as part of a longer ASCII
# identifier and is suppressed: `criticalK` (Kelvin sign) scored 0.0. There is
# no way to phrase the class so that a global `i` leaves it alone, because
# under `i` the engine cannot tell K from k at all.
#
# The policy, in English first:
#
#     A keyword matches in either ASCII case, and also where Unicode case
#     folding maps a letter onto one of its ASCII letters (ſ for s, K for k,
#     ı and İ for i). The boundary class is never folded.
#
# So the keyword side keeps every match `re.I` gave the deployed assessor —
# `crıtical` and `ſecurity advisory` still detect — while the boundary stops
# accepting those letters as ASCII. The four letters are exhaustive, not
# sampled: they are every code point that satisfies `[A-Za-z0-9_]` under
# Python `re.I`.
#
# Implemented by rewriting the pattern — each ASCII letter outside a character
# class becomes an explicit class of its cases — so that no case-insensitive
# flag is needed in either runtime. Node 20 has no scoped `(?i:...)`, so the
# port cannot use the one-line fix Python could, and the policy must not depend
# on which runtime happens to support it.
CASE_FOLD_EXTRAS = {
    "i": "İı",  # İ ı
    "k": "K",        # K Kelvin sign
    "s": "ſ",        # ſ long s
}


def caseless(pattern: str) -> str:
    """Rewrite `pattern` so its ASCII letters match case-insensitively.

    `critical` becomes `[cC][rR][iIİı][tT]...`. Escapes (`\\s`, `\\d`, `\\.`) and
    `{m,n}` quantifiers are copied verbatim. A character class inside the
    keyword keeps its cases as written and gains the fold letters of any
    i/k/s it admits, so `[a-zA-Z_]` still accepts K exactly as `re.I` did —
    the keyword side keeps every match the flag gave. Group syntax beyond
    `(?:`, `(?=`, `(?!`, `(?<=`, `(?<!` is refused rather than guessed at: a
    named group's name would otherwise be rewritten.
    """
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            end = _escape_end(pattern, i)
            out.append(pattern[i:end])
            i = end
        elif ch == "[":
            end = _class_end(pattern, i)
            out.append(_fold_class(pattern[i:end]))
            i = end
        elif ch == "{":
            end = pattern.index("}", i) + 1
            out.append(pattern[i:end])
            i = end
        elif pattern.startswith("(?", i):
            prefix = _group_prefix(pattern, i)
            out.append(prefix)
            i += len(prefix)
        elif ch.isascii() and ch.isalpha():
            low = ch.lower()
            out.append(f"[{low}{low.upper()}{CASE_FOLD_EXTRAS.get(low, '')}]")
            i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _escape_end(pattern: str, start: int) -> int:
    """Index just past the escape that opens at `start` (a backslash).

    Escapes whose tail contains letters that are *not* case-foldable text —
    hex digits, property and character names — are copied whole: rewriting
    `\\x4B` to `\\x4[bB]` would silently turn it into a different (or invalid)
    pattern. A named backreference would carry a name the rewrite cannot
    reason about, so it is refused.
    """
    kind = pattern[start + 1:start + 2]
    if kind == "x":
        return start + 4
    if kind == "u":
        if pattern.startswith("{", start + 2):
            return pattern.index("}", start) + 1
        return start + 6
    if kind == "U":
        return start + 10
    if kind in ("N", "p", "P") and pattern.startswith("{", start + 2):
        return pattern.index("}", start) + 1
    if kind == "c":
        return start + 3
    if kind == "k":
        raise ValueError(f"named backreference at {start} in {pattern!r}")
    return start + 2


def _class_end(pattern: str, start: int) -> int:
    """Index just past the `]` that closes the class opening at `start`."""
    i = start + 1
    if i < len(pattern) and pattern[i] == "^":
        i += 1
    if i < len(pattern) and pattern[i] == "]":
        i += 1  # a leading `]` is a literal
    while i < len(pattern):
        if pattern[i] == "\\":
            i += 2
            continue
        if pattern[i] == "]":
            return i + 1
        i += 1
    raise ValueError(f"unterminated character class in {pattern!r}")


def _fold_class(cls: str) -> str:
    """Add the fold letters for every i/k/s that the class `cls` admits.

    Inserted straight after `[` (or `[^`), never at the end, where a trailing
    `-` would turn them into a range. In a negated class they are excluded
    along with their ASCII letter, which is what `re.I` did too.
    """
    head = 2 if cls.startswith("[^") else 1
    body = cls[head:-1]
    admitted = _ascii_letters_in(body)
    extras = "".join(CASE_FOLD_EXTRAS[c] for c in sorted(CASE_FOLD_EXTRAS) if c in admitted)
    return cls[:head] + extras + cls[head:]


def _ascii_letters_in(body: str) -> set[str]:
    """Lowercase ASCII letters a class body admits, via literals or ranges."""
    letters: set[str] = set()
    i = 0
    while i < len(body):
        if body[i] == "\\":
            i += 2  # `\s`, `\d`, `\.` — never a letter in these patterns
            continue
        if i + 2 < len(body) and body[i + 1] == "-" and body[i + 2] != "\\":
            lo, hi = body[i], body[i + 2]
            for code in range(ord(lo), ord(hi) + 1):
                if chr(code).isascii() and chr(code).isalpha():
                    letters.add(chr(code).lower())
            i += 3
            continue
        if body[i].isascii() and body[i].isalpha():
            letters.add(body[i].lower())
        i += 1
    return letters


def _group_prefix(pattern: str, start: int) -> str:
    """The group opener at `start`, or an error for syntax `caseless` refuses."""
    for prefix in ("(?<=", "(?<!", "(?:", "(?=", "(?!"):
        if pattern.startswith(prefix, start):
            return prefix
    raise ValueError(f"unsupported group syntax at {start} in {pattern!r}")


def bounded(pattern: str) -> str:
    """Wrap `pattern` in the boundary policy on both sides."""
    return f"{LEFT}(?:{pattern}){RIGHT}"


def bounded_caseless(pattern: str) -> str:
    """`bounded()`, with the keyword case-insensitive and the edges not.

    Compile the result WITHOUT `re.I`: that flag would fold the boundary class
    too, which is the defect this function exists to prevent.
    """
    return bounded(caseless(pattern))


def bounded_left(pattern: str) -> str:
    """Left edge only.

    For patterns that end in an open-ended run — `\\S+`, `[^\\s]+` — where a
    right edge would be meaningless or actively wrong, because the match is
    already defined as continuing to whitespace.
    """
    return f"{LEFT}(?:{pattern})"
