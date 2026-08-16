"""Unicode boundary mutation corpus.

Issue #3 was one bug in one dialect. The class behind it is architectural:
security semantics resting on what a regex dialect happens to think a word is.
Fixing eleven fixtures closes eleven fixtures; this module closes the family by
mutating *every detection atom* at its boundaries and asserting that no
Unicode-only mutation can make a payload look safer.

The generator is finite and enumerable on purpose — not fuzzing. Every case has
a name that says what it is (`letter-suffix-U+00E9`), so a failure points at a
codepoint rather than a seed.

Two edge alphabets, because they behave differently and the difference is the
whole finding:

  LETTER_EDGES   characters that are *letters* in Unicode's sense but outside
                 ASCII. These are the evasion: Python's `\\w` counts them,
                 JavaScript's does not, so `\\b` disagrees across runtimes.

  FORMAT_EDGES   combining marks, zero-width joiners, bidi controls. These were
                 *negative controls* in the original finding — they did not
                 diverge — and they are kept precisely for that reason. A
                 control that starts failing is information.

Used by `tests/test_boundary_mutations.py` (oracle-side invariants) and by
`parity/emit_mutations.py` (cross-runtime equality).
"""
from __future__ import annotations

import unicodedata

# Non-ASCII letters, spread across scripts so the corpus is not accidentally
# Latin-1-shaped. A detector that survives é but not Ж has not been fixed.
LETTER_EDGES = [
    "é",  # é  Latin-1 Supplement
    "ü",  # ü  Latin-1 Supplement
    "α",  # α  Greek
    "Ж",  # Ж  Cyrillic
    "א",  # א  Hebrew (RTL)
    "م",  # م  Arabic (RTL)
    "क",  # क  Devanagari
    "中",  # 中 CJK
]

# Format and mark characters. Not letters; kept as controls.
FORMAT_EDGES = [
    "́",  # combining acute accent
    "​",  # zero-width space
    "‌",  # zero-width non-joiner
    "‍",  # zero-width joiner
    "‮",  # right-to-left override
    "﻿",  # zero-width no-break space / BOM
]

#: The detection atoms themselves, not prose containing them. Prose would test
#: the sentence; these test the matcher.
SEEDS = [
    "critical",
    "urgent",
    "exploit",
    "breach",
    "CVE-2024-9999",
    "immediately",
    "must upgrade",
    "security advisory",
    "You should upgrade",
    "Run the following command",
    "use this version",
    "According to the official documentation",
    "officially recommended",
    "the documentation states",
    "Fetch the complete documentation index",
    "1.2.3",
    "foo@1.2.3",
    "port: 3000",
    "npm install foo",
    "export API_KEY=xyz",
    "upgrade to version 2.0",
]


def mutations(token: str) -> dict[str, str]:
    """Every boundary mutation of one detection atom, keyed by what it is."""
    cases = {
        "baseline": token,
        "nfc": unicodedata.normalize("NFC", token),
        "nfd": unicodedata.normalize("NFD", token),
    }

    for edge in LETTER_EDGES:
        cases[f"letter-prefix-U+{ord(edge):04X}"] = edge + token
        cases[f"letter-suffix-U+{ord(edge):04X}"] = token + edge

    for edge in FORMAT_EDGES:
        cases[f"format-prefix-U+{ord(edge):04X}"] = edge + token
        cases[f"format-suffix-U+{ord(edge):04X}"] = token + edge

    return cases


def corpus() -> list[dict]:
    """Flatten to `{id, seed, mutation, content}` records."""
    out = []
    for seed in SEEDS:
        for name, content in mutations(seed).items():
            out.append({
                "id": f"{seed}::{name}",
                "seed": seed,
                "mutation": name,
                "content": content,
            })
    return out


#: Mutations that are allowed to change the outcome, with the reason.
#:
#: `nfd` decomposes a precomposed letter into base + combining mark, which is a
#: genuinely different string. Whether the detector should normalize before
#: matching is a real policy question (see SECURITY.md), not a parity bug — and
#: it is held to *cross-runtime equality* regardless, just not to equality with
#: the baseline.
BASELINE_EXEMPT = {"nfd"}


if __name__ == "__main__":
    import json

    for record in corpus():
        print(json.dumps(record, ensure_ascii=False))
