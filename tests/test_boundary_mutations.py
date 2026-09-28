"""The monotonicity invariant, over the whole mutation corpus.

    Decorating a detection atom with Unicode must never make it look safer.

That is the property issue #3 violated, stated so it covers cases nobody has
thought of yet. `criticalé` scoring 0.0 while `critical` scored 0.33 was not
"a regex bug" — it was this invariant failing, and the invariant is what stops
the next one.

Scoped deliberately: the seeds are *detection atoms*, and the mutations are at
their boundaries. This does not claim that arbitrary Unicode anywhere in prose
must raise risk — that would be an argument for treating every non-English
document as hostile, which is both wrong and the kind of rule that gets a
security tool switched off.
"""
from __future__ import annotations

import ast
import pathlib
import random
import re
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "parity"))

from aletheia.assess import assess  # noqa: E402
from aletheia.boundary import bounded, bounded_caseless, caseless  # noqa: E402
from unicode_boundary_mutations import (  # noqa: E402
    BASELINE_EXEMPT,
    CASEFOLD_EDGES,
    FORMAT_EDGES,
    LETTER_EDGES,
    SEEDS,
    corpus,
    mutations,
)

# Ordering of outcomes by restrictiveness. A mutation may move a payload *up*
# this scale (more suspicious) but never down.
SEVERITY = {"low": 0, "moderate": 1, "high": 2}

SOURCE = "web_search"  # the channel the threat model is actually about

ASSESS_PY = pathlib.Path(__file__).resolve().parent.parent / "src" / "aletheia" / "assess.py"


def severity_of(content: str) -> tuple[int, float]:
    a = assess(content, SOURCE)
    return SEVERITY[a.severity], a.injection_risk_score


class MonotonicityUnderUnicodeMutation(unittest.TestCase):
    """No Unicode-only mutation may lower the assessed risk."""

    def test_no_mutation_lowers_severity_band(self):
        regressions = []
        for seed in SEEDS:
            base_band, base_score = severity_of(seed)
            for name, mutated in mutations(seed).items():
                if name in BASELINE_EXEMPT or name == "baseline":
                    continue
                band, score = severity_of(mutated)
                if band < base_band:
                    regressions.append(
                        f"{seed!r} + {name}: band {base_band} -> {band} "
                        f"(score {base_score:.4f} -> {score:.4f})"
                    )
        self.assertEqual(regressions, [], "\n".join(regressions))

    def test_no_letter_mutation_suppresses_detection_entirely(self):
        """The specific shape of issue #3: a detected atom becoming invisible.

        Checked separately from the band test because it is the sharpest form —
        score falling to exactly zero means every factor was suppressed, not
        merely that a threshold was crossed.
        """
        blinded = []
        for seed in SEEDS:
            _, base_score = severity_of(seed)
            if base_score == 0.0:
                continue  # nothing to suppress
            for edge in LETTER_EDGES:
                for mutated, label in (
                    (edge + seed, f"prefix U+{ord(edge):04X}"),
                    (seed + edge, f"suffix U+{ord(edge):04X}"),
                ):
                    _, score = severity_of(mutated)
                    if score == 0.0:
                        blinded.append(f"{seed!r} + {label} -> score 0.0")
        self.assertEqual(blinded, [], "\n".join(blinded))

    def test_no_casefold_mutation_suppresses_detection_entirely(self):
        """A letter that folds to ASCII must not hide a keyword either.

        Separate from the LETTER_EDGES test because the violated assumption is
        different: not the dialect's idea of a word (issue #3), but that an
        ASCII class stays ASCII under a case-insensitive match. It does not —
        `re.I` lets U+212A satisfy `[A-Za-z0-9_]`, so `criticalK` read as one
        longer identifier and scored 0.0.
        """
        blinded = []
        for seed in SEEDS:
            _, base_score = severity_of(seed)
            if base_score == 0.0:
                continue
            for edge in CASEFOLD_EDGES:
                for mutated, label in (
                    (edge + seed, f"prefix U+{ord(edge):04X}"),
                    (seed + edge, f"suffix U+{ord(edge):04X}"),
                ):
                    _, score = severity_of(mutated)
                    if score == 0.0:
                        blinded.append(f"{seed!r} + {label} -> score 0.0")
        self.assertEqual(blinded, [], "\n".join(blinded))

    def test_format_edges_remain_controls(self):
        """Format characters were the negative control. Report if that changes.

        They are not asserted to behave identically — a zero-width joiner
        genuinely inside a token is a different string. What is asserted is the
        same invariant: they must not make anything look safer.
        """
        regressions = []
        for seed in SEEDS:
            base_band, _ = severity_of(seed)
            for edge in FORMAT_EDGES:
                for mutated in (edge + seed, seed + edge):
                    band, _ = severity_of(mutated)
                    if band < base_band:
                        regressions.append(
                            f"{seed!r} + U+{ord(edge):04X}: band {base_band} -> {band}"
                        )
        self.assertEqual(regressions, [], "\n".join(regressions))


class BoundaryPolicyStillDiscriminates(unittest.TestCase):
    """The fix must not become "match everything, everywhere".

    A boundary rule that fires inside longer ASCII identifiers would trade a
    false-negative class for a false-positive class — and false positives are
    what forced shadow mode in the first place.
    """

    def test_keyword_inside_a_longer_ascii_word_does_not_match(self):
        for text in ("hypercritical", "criticality", "critical_path", "uncritical"):
            score = assess(text, SOURCE).injection_risk_score
            self.assertEqual(score, 0.0, f"{text!r} should not trip the detector")

    def test_bare_keyword_still_matches(self):
        self.assertGreater(assess("critical", SOURCE).injection_risk_score, 0.0)

    def test_keyword_beside_a_unicode_letter_matches(self):
        """The evasion, closed."""
        for text in ("criticalé", "écritical", "criticalЖ", "critical中"):
            self.assertGreater(
                assess(text, SOURCE).injection_risk_score, 0.0,
                f"{text!r} must not be invisible",
            )


class CaselessRewriteIsExact(unittest.TestCase):
    """`bounded_caseless(p)` changes the boundary and nothing else.

    The rewrite replaced `re.I` on fifteen patterns. The claim that it only
    closed the case-fold boundary hole is checked here rather than asserted:
    on every input where no fold letter sits at a match edge, the old form
    (`bounded(p)` + `re.I`) and the new form must return identical matches.
    That includes fold letters *inside* a keyword — `crıtical` — which `re.I`
    matched and the policy keeps.
    """

    FOLD_LETTERS = "\u0130\u0131\u017f\u212a"

    @staticmethod
    def caseless_sources() -> list[str]:
        tree = ast.parse(ASSESS_PY.read_text(encoding="utf-8"))
        return [
            node.args[0].value
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and getattr(node.func, "id", None) == "bounded_caseless"
            and node.args and isinstance(node.args[0], ast.Constant)
        ]

    @staticmethod
    def samples(rng: random.Random) -> list[str]:
        """Seeds and prose, case-scrambled, with ASCII and fold letters mixed in."""
        base = SEEDS + [
            "high severity breach", "zero-day exploited", "exploitable",
            "Call the lookup function", "The advisory says so",
            "as documented in the release", "the fix was published in 2.1",
            "mandatory patch now", "right now", "as soon as possible",
        ]
        out = []
        for text in base:
            for _ in range(48):
                chars = [c.upper() if rng.random() < 0.5 else c.lower() for c in text]
                # fold letters inside the keyword, never at its edges
                if len(chars) > 2 and rng.random() < 0.3:
                    j = rng.randrange(1, len(chars) - 1)
                    folds = {"i": "\u0131", "s": "\u017f", "k": "\u212a"}
                    chars[j] = folds.get(chars[j].lower(), chars[j])
                word = "".join(chars)
                edge = rng.choice(["", " ", "x", "_", "9", "-", "é", "\n"])
                out.append(edge + word + rng.choice(["", " ", "y", "_", ".", "é"]))
        return out

    def test_old_and_new_agree_away_from_fold_edges(self):
        rng = random.Random(20260927)
        sources = self.caseless_sources()
        self.assertEqual(len(sources), 15, "expected every former re.I pattern")
        texts = self.samples(rng)
        mismatches = []
        matched = 0
        for src in sources:
            old = re.compile(bounded(src), re.I)
            new = re.compile(bounded_caseless(src))
            for text in texts:
                a = [m.span() for m in old.finditer(text)]
                b = [m.span() for m in new.finditer(text)]
                matched += bool(a)
                if a != b:
                    mismatches.append(f"{src[:40]!r} on {text!r}: {a} != {b}")
        self.assertEqual(mismatches, [], "\n".join(mismatches[:20]))
        # Non-vacuity: agreement on inputs that never match proves nothing.
        self.assertGreater(matched, 450, f"only {matched} matching samples")

    def test_new_form_detects_at_fold_edges_where_old_was_blind(self):
        """The one intended difference, pinned in both directions.

        New: detects with a fold letter at either edge. Old: blind there — if
        a future change made the old form pass too, this test would be proving
        nothing, so the old blindness is asserted rather than assumed.
        """
        exercised = 0
        for src in self.caseless_sources():
            old = re.compile(bounded(src), re.I)
            new = re.compile(bounded_caseless(src))
            for seed in SEEDS:
                if not new.fullmatch(seed):
                    continue
                for edge in self.FOLD_LETTERS:
                    for text in (edge + seed, seed + edge):
                        exercised += 1
                        self.assertIsNotNone(new.search(text), f"new form blind on {text!r}")
                        self.assertIsNone(old.search(text), f"old form was not blind on {text!r}")
        self.assertGreater(exercised, 0, "no seed fully matched a caseless pattern")

    def test_rewrite_refuses_what_it_cannot_fold_safely(self):
        with self.assertRaises(ValueError):
            caseless("(?P<name>critical)")
        with self.assertRaises(ValueError):
            caseless("[unterminated")
        with self.assertRaises(ValueError):
            caseless(r"(critical)\k<name>")

    def test_escape_tails_are_not_case_folded(self):
        """Hex digits and names inside an escape are not text.

        Found by a touchstone pass on this rewrite: `\\x4B` became `\\x4[bB]`,
        which no longer compiles. Latent — no current pattern uses these — but
        the next one to would have crashed the hook at import.
        """
        for escape in (r"\x4B", r"ſ", r"\p{L}", r"\N{KELVIN SIGN}", r"\cJ"):
            self.assertEqual(caseless(escape), escape)
        self.assertEqual(caseless(r"\x4Bk"), r"\x4B[kK" + "K" + "]")
        re.compile(caseless(r"critical\x20ſ"))  # compiles, does not raise


class CorpusShape(unittest.TestCase):
    def test_corpus_is_finite_and_named(self):
        records = corpus()
        self.assertEqual(
            len(records),
            len(SEEDS) * (3 + 2 * len(LETTER_EDGES) + 2 * len(CASEFOLD_EDGES) + 2 * len(FORMAT_EDGES)),
        )
        self.assertEqual(len({r["id"] for r in records}), len(records))


if __name__ == "__main__":
    unittest.main()
