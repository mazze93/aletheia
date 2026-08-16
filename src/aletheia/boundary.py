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


def bounded(pattern: str) -> str:
    """Wrap `pattern` in the boundary policy on both sides."""
    return f"{LEFT}(?:{pattern}){RIGHT}"


def bounded_left(pattern: str) -> str:
    """Left edge only.

    For patterns that end in an open-ended run — `\\S+`, `[^\\s]+` — where a
    right edge would be meaningless or actively wrong, because the match is
    already defined as continuing to whitespace.
    """
    return f"{LEFT}(?:{pattern})"
