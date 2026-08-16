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

import sys
import pathlib
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "parity"))

from aletheia.assess import assess  # noqa: E402
from unicode_boundary_mutations import (  # noqa: E402
    BASELINE_EXEMPT,
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


class CorpusShape(unittest.TestCase):
    def test_corpus_is_finite_and_named(self):
        records = corpus()
        self.assertEqual(len(records), len(SEEDS) * (3 + 2 * len(LETTER_EDGES) + 2 * len(FORMAT_EDGES)))
        self.assertEqual(len({r["id"] for r in records}), len(records))


if __name__ == "__main__":
    unittest.main()
