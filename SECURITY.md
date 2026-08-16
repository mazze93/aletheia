# Security posture

Aletheia is a detection layer, not a control. This file states what she is
trusted to do, what she is known not to catch, and why she does not block by
default.

## Threat model

**In scope.** Indirect prompt injection: content arriving from a low-trust
channel (web search, web fetch, MCP tool output, pasted logs) that is shaped to
look like instruction, and that supplies a *governing parameter* — a version, a
path, a command — meant to be acted on as if the principal had said it.

**Out of scope, and deliberately so.**

- The `user` channel. The principal is trusted at 1.0 by construction. An
  instruction pasted by a human as if it were their own is not distinguishable
  here and is not attempted.
- The agent's own momentum. She cannot score the urge to finish a task.
- Anything after the decision. She annotates and, optionally, denies a tool
  call. She does not sandbox, does not revoke credentials, does not contain a
  process that has already run.

The two channels hardest to guard are the ones labelled *self*. That limit is
kept in the record on purpose.

## Why shadow mode is the default

Enforcement is opt-in (`ALETHEIA_MODE=enforce`). This is a security decision,
not timidity.

A detector that has never been measured against real traffic does not know its
own false-block rate. Aletheia's was measured, and it was disqualifying: scored
lexically, **remediation work is indistinguishable from injection.** Both name
versions, both carry urgency, both instruct. A real Dependabot PR body scored
**0.82** against a stop threshold of 0.6 and would have blocked the shipping of
a security fix. Editing this repository's own documentation scored the same.

A security layer that blocks patching is a vulnerability with good intentions.
So she starts by watching, writes what she *would* have done to
`~/.claude/aletheia/audit.jsonl`, and earns enforcement from evidence.

## Where enforcement is meaningful

Not at the vocabulary — at the provenance boundary. `policy.py` blocks when
content **carrying declared taint** reaches a destructive or egress tool. Taint
is propagated explicitly by whoever knows the origin; it is never re-inferred
from the words in the payload, because that inference is exactly the one that
cannot separate an advisory from an attack quoting one.

Corollary, stated as a rule: **never block dependency remediation on
advisory-like text alone.** Validate a version at its registry, not at its
vocabulary.

## Lexical boundaries are policy, not defaults

`\b` is not a security boundary. It means "a transition between `\w` and `\W`",
and Python and JavaScript disagree about `\w` — Python's is Unicode-aware for
`str` patterns, JavaScript's is ASCII-only. Security semantics were resting on
that difference.

Two evasions followed, in opposite directions, and both are closed:

| | Python | TypeScript |
|---|---|---|
| `café@1.2.3` | governing parameter | **invisible** |
| `criticalé` | **score 0.0** | matched |

Note which column is wrong in each row: neither implementation was reliably
the correct one, which is why parity is a drift detector and not a referee.

`src/aletheia/boundary.py` and `typescript/src/boundary.ts` now state the rule
explicitly instead of inheriting a default:

> Match a security keyword unless it is embedded inside a larger ASCII
> identifier. Unicode letters adjacent to it do not suppress a detection.

So `criticalé`, `écritical`, `criticalЖ` and `critical中` all match, while
`hypercritical` and `critical_path` do not — the false-negative class closes
without opening a false-positive one.

A second, narrower dialect split surfaced the same way: ECMAScript counts
U+FEFF as whitespace and Python does not, so `\S+` captured a different
*extent*. `NOT_SPACE` pins it. Extent matters because `governing_parameters` is
the list a human is told to verify at a registry, and a trailing invisible
character makes that verification fail silently.

**This is enforced, not remembered.** `tests/test_boundary_inventory.py` fails
the build if `\b` or `\B` reappears in either assessor, and `\w` requires an
allowlist entry naming the port's equivalent. `parity/` runs 651 mutation cases
— every detection atom decorated at both boundaries with letters from eight
scripts plus combining marks, zero-width joiners and bidi controls — across both
runtimes. `tests/test_boundary_mutations.py` asserts the invariant that
generalises the fix: **no Unicode-only mutation may make a payload look safer.**

## Normalization

`assess()` does **not** normalize before matching, deliberately. Normalizing
would mean the string reported in `governing_parameters` is not the string that
was present, and silently rewriting evidence is a worse failure than missing a
decomposed match. The cost — NFD and NFC forms can score differently — is
recorded, held to cross-runtime equality, and tested in
`tests/test_thresholds.py` rather than left to chance.

## Known gaps

- **Quiet structural injection is missed.** `evals/malicious/incident-devserver.txt`
  — structured JSON supplying `runtimeExecutable`, the `preview_start` RCE shape
  — scores 0.26 and passes. It carries no urgency, no authority claim and no
  imperative, so four of five pattern families stay silent. Tracked as issue #1
  and asserted as a *known failure* in `tests/test_evals.py`, so it cannot
  quietly start passing without someone noticing.
- **Lexical detection is evadable.** Patterns are regexes. Paraphrase defeats
  them. She raises the cost of a naive attack; she does not raise it to
  infinity. Visual homoglyph deception and model-level paraphrase are separate
  classes with separate mitigations, untouched by the boundary work above.
- **Python and TypeScript still differ above the assessor.** The TypeScript
  side has no policy, provenance or audit layer (issue #2). Parity covers
  `assess()` only; claiming more would be false advertising. Use the Python
  package — not because it adjudicates, but because it is the only one that
  implements the full stack.
- **Audit records hashes, not spans.** A future evasion is currently
  explainable only down to which factors fired, not where they matched. Storing
  raw input and match offsets would make forensics much better and would also
  turn the audit log into a plaintext archive of everything the agent read —
  an unresolved tension, not an oversight. See the journal.

## Before enabling enforce mode

- [x] issue #3 quarantined vectors promoted to normal parity fixtures
- [x] boundary mutation corpus runs in CI against Python and TypeScript
- [x] NFC/NFD policy specified and tested rather than accidental
- [x] every `\b` / `\B` / `\w` inventoried, replaced, or allowlisted with a reason
- [x] the six must-not-block fixtures pass **under enforcement**
- [x] threshold-edge behaviour asserted at 0.2999 / 0.3 / 0.5999 / 0.6
- [x] factor-, score-, band- and action-level parity all mandatory
- [x] hook-level enforce-mode regression: the adapter blocks (exit 2) on an
      adversarial payload and records the block with factor IDs and action
      (`tests/test_hook_enforce.py`)
- [ ] **issue #1 is a blocker, not a gap.** Measured: `incident-devserver.txt`
      scores 0.26 from `web_fetch` and 0.21 from `mcp_tool`, and both resolve to
      `proceed` under enforcement. A labelled incident would pass a live gate.
      Close it or accept it in writing, with a named owner.
- [ ] audit output carries match spans so an evasion is explainable after the
      fact — an unresolved trade against plaintext retention, not a missing
      feature. Needs a named owner and a hard pre-enforcement disposition.

## Audit log

`~/.claude/aletheia/audit.jsonl`, append-only, one JSON object per event.

It stores a **content hash, not the content.** Aletheia sits on the channel
where web results, file contents and command text pass; writing those verbatim
would turn a security tool into a plaintext archive of everything the agent
touched. Raw capture requires `ALETHEIA_AUDIT_RAW=1`, set deliberately and
never by default.

## Reporting

Private repository. Raise an issue, or if the finding is itself sensitive, keep
it out of the issue text and reference it indirectly.
