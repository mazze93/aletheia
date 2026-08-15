# Aletheia

*Ἀλήθεια* — truth as the removal of concealment.

A prompt-injection detection agent for Claude. She tracks the **provenance** of
content and flags the moment an untrusted source tries to supply a parameter
that will govern an action — a version number, a file path, a command — and have
it acted on as if the user had said it.

Born 2026-06-17 from a live injection incident. The why is in
[`CLAUDE.md`](./CLAUDE.md); the posture and known gaps are in
[`SECURITY.md`](./SECURITY.md); this file is the how.

## The idea

Injection works when content from a low-trust source arrives structured to look
like instruction, carries urgency, claims authority, and names specific values
meant to be acted on — and the agent treats those values as if they came from
the principal. The fix is not blanket skepticism (that makes an agent useless).
The fix is provenance: **every parameter that governs an action must have a
declared source, and untrusted sources cannot supply governing parameters
without the human knowing.**

| source | trust | |
|--------|-------|--|
| `user` | 1.0 | the principal — what they say governs |
| `agent` | 0.95 | the agent acting on the principal's instruction |
| `file` | 0.9 | the codebase, committed, version-controlled |
| `mcp_tool` | 0.5 | depends on the tool; can be compromised |
| `web_search` / `web_fetch` | 0.2 | can be crafted — was crafted |
| `clipboard` | 0.1 | unknown origin; maximum suspicion |
| `unclassified` | 0.3 | **audit and ask — not "untrusted"** |

## Judging and enforcing are separate

This is the load-bearing design decision, and it was learned the hard way.

```
assess.py       classify content, explain the score.        Decides nothing.
provenance.py   where it came from; trust and carried taint.
policy.py       the only module that may decide to block.
audit.py        append-only JSONL; hashes, not payloads.
hooks.py        Claude adapter: payload shape, exit semantics.
cli.py          what a hook actually invokes.
```

The original design let the score *be* the decision. Measured against real
traffic, that is disqualifying — because **remediation work is linguistically
identical to injection.** Both name versions, both carry urgency, both tell you
to run something.

| payload | score | old design | now |
|---|---|---|---|
| `npm audit fix` | 0.25 | proceed | proceed |
| commit message with a version table | 0.49 | warn | proceed |
| a real Dependabot PR body | **0.82** | **blocked** | proceed |
| editing docs that quote an injection | **0.82** | **blocked** | proceed |
| the same text arriving from `web_search` | 0.88 | blocked | **blocked** |

The last row is the point. Nothing was made more permissive about *external
content*; what changed is that a score is no longer allowed to mean anything on
its own. `policy.py` asks where the content came from, whether taint was
carried into it, and whether it reaches an effect that matters.

**Taint is carried, never inferred.** If a command derives from external
content, that fact travels with it explicitly. It is not re-derived from the
presence of the word "critical", because that inference cannot separate a
security advisory from an attack quoting one.

## Shadow mode

She starts in shadow mode and **blocks nothing**. Every event is scored, decided
and written to `~/.claude/aletheia/audit.jsonl` with the action that *would*
have been enforced.

```bash
# what would have been blocked, this week
jq -r 'select(.would_block) | [.ts,.tool,.origin,.score,.action] | @tsv' \
  ~/.claude/aletheia/audit.jsonl
```

Enforcement is opt-in via `ALETHEIA_MODE=enforce`, and should stay off until
that log shows a false-block rate you can live with. A security layer that
blocks patching is a vulnerability with good intentions.

## Run it

Python 3.11+, standard library only. No install required.

```bash
PYTHONPATH=src python3 -m aletheia.cli --source web_search < evals/malicious/incident-websearch.txt
PYTHONPATH=src python3 -m aletheia.cli --source web_search < evals/benign/benign-websearch.txt
PYTHONPATH=src python3 -m aletheia.cli --mode enforce --source web_search < evals/malicious/incident-websearch.txt   # exit 2
```

Or install it: `pip install -e .` then `aletheia --source web_search < file`.

## Wire into Claude Code

```bash
cp integrations/claude-code/settings.example.json /tmp/aletheia-hooks.json
# merge the "hooks" block into ~/.claude/settings.json
```

Only `PostToolUse` on `WebSearch|WebFetch` is wired — the channel where
provenance is meaningful and where her calibration is measured. A
`PreToolUse Bash|Edit|Write` hook is deliberately **not** wired; see
`SECURITY.md` for the measurement that removed it.

## Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -t .
```

Deterministic, no network, no model. `tests/test_regressions.py` holds the cases
that broke — real payloads from real maintenance work — and asserts them in
*enforce* mode, because passing only in shadow mode would prove nothing.
`tests/test_evals.py` asserts known failures still fail, so a gap cannot quietly
close without someone noticing.

## What she does not do

She is a layer, not a cure. She does not audit the `user` channel (trust 1.0 by
design), and she cannot score the agent's own momentum. The two channels hardest
to guard are the ones labelled *self*: an instruction pasted as if from the
principal, and the agent's own urge to finish. Those limits are real and are
kept in the record on purpose.

MIT.
