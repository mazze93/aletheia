"""Run the eval corpus and hold known failures visible.

A known failure that quietly becomes a passing test is how a security tool
forgets what it cannot do. `expect_known_failure` cases are asserted to *still
fail* — when one starts passing, this suite fails loudly and tells you to close
the issue and drop the flag.
"""
from __future__ import annotations

import json
import pathlib
import unittest

from aletheia import policy
from aletheia.assess import assess
from aletheia.policy import decide
from aletheia.provenance import build

EVALS = pathlib.Path(__file__).resolve().parent.parent / "evals"


def load_cases():
    with (EVALS / "expected.jsonl").open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


class EvalCorpus(unittest.TestCase):
    def test_corpus(self):
        surprises = []
        for case in load_cases():
            content = (EVALS / case["file"]).read_text(encoding="utf-8")
            event = build(content=content, origin=case["origin"],
                          event="PostToolUse")
            a = assess(content, event.origin)
            d = decide(event, a.injection_risk_score, mode=policy.ENFORCE,
                       reasoning=a.reasoning)
            expected = case["expect_action"]
            known_failure = case.get("expect_known_failure", False)
            matched = d.action == expected

            if known_failure and matched:
                surprises.append(
                    f"{case['file']}: known failure now PASSES "
                    f"(score {a.injection_risk_score:.2f}). Close the issue and "
                    "remove expect_known_failure."
                )
            elif not known_failure and not matched:
                surprises.append(
                    f"{case['file']}: expected {expected}, got {d.action} "
                    f"(score {a.injection_risk_score:.2f})"
                )

        self.assertEqual(surprises, [], "\n".join(surprises))


if __name__ == "__main__":
    unittest.main()
