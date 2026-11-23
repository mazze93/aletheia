# Class-closure checklist

A security finding is not resolved when the reported payload stops working. It is resolved, **within a stated scope**, when the failure-producing assumption is replaced by an explicit policy and the system can demonstrate that the class cannot silently recur.

Use this after any Aletheia (or sibling gate) finding that looks like “one more pattern.”

## Checklist

1. **Reproduce** the exploit through the deployed or deployable path (hook, CLI, parity runner) — not only a synthetic unit test.
2. **Name the unsafe assumption** — not merely the broken test or the one string that failed.
3. **Write the intended security behavior** as an explicit, human-reviewable policy.
4. **Repair every implementation** that enforces or represents that policy (Python and TypeScript assessors, at minimum).
5. **Generate adversarial variants** over the relevant transformation space (scripts, controls, folds) — not only known strings.
6. **Encode a monotonic or non-bypass invariant** where possible (e.g. Unicode-only mutations must not lower assessed risk).
7. **Add a structural regression gate** against unsafe primitives and stale evidence (CI inventory, corpus freshness).
8. **Test at the real enforcement boundary**, including telemetry (shadow and enforce), not only `assess()` scores.
9. **Publish scope of closure and remaining perimeter** — what this instrument still cannot see.

## Product of a closed class

A finding should create an **instrument**, not merely a patch:

| Artifact | Role |
|---|---|
| Policy object | Named semantics humans can review |
| Adversarial corpus | Executable tests of the transformation space |
| Invariant test | Machine-checkable non-bypass property |
| CI control | Blocks silent re-entry of the unsafe primitive |
| Decision / SECURITY record | Auditable “why” and open perimeter |
| Enforcement-layer evidence | Proof at the hook, not only the library |

## Worked example

Unicode boundary evasion → explicit ASCII-identifier boundary policy → dual-runtime helpers → mutation corpus + inventory CI → documented perimeter in `SECURITY.md` and [`unicode-boundary-evasion.md`](./unicode-boundary-evasion.md).

## Anti-patterns

- Closing the ticket when one payload stops matching.
- Using cross-runtime parity as the semantic judge.
- Claiming enforce mode while only library tests are green.
- Leaving the remaining perimeter unstated so the next session inherits false confidence.
