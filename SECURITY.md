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
`~/.claude/audit.jsonl`, and earns enforcement from evidence.

## Where enforcement is meaningful

Not at the vocabulary — at the provenance boundary. `policy.py` blocks when
content **carrying declared taint** reaches a destructive or egress tool. Taint
is propagated explicitly by whoever knows the origin; it is never re-inferred
from the words in the payload, because that inference is exactly the one that
cannot separate an advisory from an attack quoting one.

Corollary, stated as a rule: **never block dependency remediation on
advisory-like text alone.** Validate a version at its registry, not at its
vocabulary.

## Known gaps

- **Quiet structural injection is missed.** `evals/malicious/incident-devserver.txt`
  — structured JSON supplying `runtimeExecutable`, the `preview_start` RCE shape
  — scores 0.26 and passes. It carries no urgency, no authority claim and no
  imperative, so four of five pattern families stay silent. Tracked as issue #1
  and asserted as a *known failure* in `tests/test_evals.py`, so it cannot
  quietly start passing without someone noticing.
- **Lexical detection is evadable.** Patterns are regexes. Paraphrase defeats
  them. She raises the cost of a naive attack; she does not raise it to
  infinity.
- **Python and TypeScript can drift.** `typescript/` still carries the
  pre-refactor design and has no policy layer. Until it is ported, treat the
  Python package as authoritative.

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
