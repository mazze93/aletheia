"""Enforcement. The only module permitted to decide that something blocks.

`assess()` classifies and explains. It does not decide, and it does not know
about exit codes. That separation is the correction at the heart of this
package: previously a lexical score *was* the decision, so a high score on
agent-authored text became a block on legitimate work.

A score is one input here. Origin, taint, event type, tool capability and
reversibility are the others.

Modes
-----
`shadow`   — decide, record, and surface, but every outcome exits 0. Nothing is
             ever blocked. This is the mode Aletheia starts in, and it stays
             there until real telemetry earns the alternative.
`enforce`  — blocking decisions block.

Shadow mode is not a debug flag. An injection detector that has never been
measured against real traffic does not know its own false-block rate, and a
false block on `git`, package remediation or PR creation is a high-severity
usability regression — not a tuning nit.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .provenance import Event, UNTRUSTED, UNCLASSIFIED, EXTERNAL_INSTRUCTIONAL

SHADOW = "shadow"
ENFORCE = "enforce"

PROCEED = "proceed"
VERIFY = "verify"
STOP = "stop"

# Score bands, applied only where the score is meaningful — i.e. to content
# that arrived from somewhere else.
VERIFY_AT = 0.3
STOP_AT = 0.6


@dataclass
class Decision:
    action: str          # proceed | verify | stop
    exit_code: int       # what the adapter should exit with
    enforced: bool       # would this have blocked, and did it?
    reason: str
    mode: str = SHADOW

    @property
    def would_block(self) -> bool:
        return self.action == STOP


def decide(event: Event, score: float, mode: str = SHADOW,
           reasoning: str = "") -> Decision:
    """Map (provenance, capability, score) -> action.

    The ordering of these rules is the policy. Read them top to bottom.
    """
    action, reason = _classify(event, score, reasoning)

    # Shadow mode collapses every outcome to exit 0. The decision is still
    # computed and recorded in full — that is the entire point of the mode.
    if mode != ENFORCE:
        return Decision(action, 0, False, reason, mode)

    if action == STOP:
        return Decision(action, 2, True, reason, mode)
    if action == VERIFY:
        return Decision(action, 1, False, reason, mode)
    return Decision(action, 0, False, reason, mode)


def _classify(event: Event, score: float, reasoning: str) -> tuple[str, str]:
    # 1. The agent's own planned action, with no taint carried into it.
    #    Lexical risk here is not provenance. A commit message describing a CVE
    #    fix reads exactly like the injection it is fixing; that resemblance
    #    carries no information about where the instruction came from.
    if event.agent_authored:
        return PROCEED, (
            "Agent-authored action with no external taint. Lexical risk is not "
            f"provenance; score {score:.2f} recorded, not enforced."
        )

    # 2. Tainted content reaching an effect that materialises harm. This is the
    #    path that actually matters, and the one worth gating.
    if event.tainted and (event.destructive or event.egress):
        return STOP, (
            "Action derives from external content "
            f"({', '.join(event.taint)}) and reaches a "
            f"{'destructive' if event.destructive else 'egress'} tool "
            f"({event.tool}). Confirm explicitly before proceeding. {reasoning}"
        ).strip()

    # 3. Dependency remediation is never blocked on advisory-like text alone.
    #    Advisories are *supposed* to name versions urgently. Validate at the
    #    registry instead of at the vocabulary.
    if event.tainted and EXTERNAL_INSTRUCTIONAL in event.taint and not event.destructive:
        return VERIFY, (
            "Carries external instructional content. Verify any version, path "
            f"or command at its registry — not at the source that supplied it. {reasoning}"
        ).strip()

    # 4. Inbound content from an untrusted channel: the indirect-injection
    #    surface, and where the score is genuinely informative.
    if event.trust_class == UNTRUSTED:
        if score >= STOP_AT:
            return STOP, reasoning or f"High injection risk ({score:.2f}) from {event.origin}."
        if score >= VERIFY_AT:
            return VERIFY, reasoning or f"Moderate injection risk ({score:.2f}) from {event.origin}."
        return PROCEED, reasoning or f"Low injection risk ({score:.2f}) from {event.origin}."

    # 5. Semi-trusted (MCP tool output): can be compromised, but is not the
    #    open web. Verify at high confidence; never auto-stop on lexis alone.
    if event.trust_class not in (UNTRUSTED, UNCLASSIFIED):
        if score >= STOP_AT:
            return VERIFY, reasoning or f"Elevated risk ({score:.2f}) from {event.origin}."
        return PROCEED, reasoning or f"Low risk ({score:.2f}) from {event.origin}."

    # 6. Unclassified provenance. The fail-safe is audit-and-ask, never stop.
    #    Not knowing where something came from is a reason to look, not a
    #    reason to assume hostility.
    if score >= STOP_AT:
        return VERIFY, (
            f"Unclassified provenance with elevated lexical risk ({score:.2f}). "
            "Recorded for review; unclassified is not untrusted. " + reasoning
        ).strip()
    return PROCEED, reasoning or f"Unclassified provenance, low risk ({score:.2f})."
