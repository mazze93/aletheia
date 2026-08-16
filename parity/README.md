# parity

Two implementations of one contract drift silently unless something makes them
argue. This directory is the argument.

```
vectors.jsonl        52 cases, language-neutral, one per mirrored joint
emit.py              the oracle projects them            → assess.golden.json
emit.ts              the port projects them              → /tmp/ts.json
compare.py           diffs the two, names the joint that broke
assess.golden.json   committed; regenerating it is a CI gate
```

Run it:

```bash
python3 parity/emit.py > parity/assess.golden.json   # regenerate after any change
npx tsx parity/emit.ts > /tmp/ts.json                # from typescript/ deps
python3 parity/compare.py parity/assess.golden.json /tmp/ts.json
```

## The Python side is the reference, not the authority

`src/aletheia/assess.py` is where the golden fixtures are generated from, so
that regeneration has one unambiguous source. Borrowed from
`cognitive/stratum`, which pairs a Python semantics reference with a TypeScript
core for the same reason.

**Being the reference is not being right.** A parity difference proves the two
implementations disagree and nothing more; deciding which behaviour is correct
is a policy question, and the answer is written down before either side moves.
The reference has been the wrong one: on U+FEFF the port's reading was better,
and Python was corrected to conform.

To change behaviour deliberately:

1. Decide what it should be and record why.
2. Make both implementations conform.
3. Regenerate the goldens.

## What the projection compares, and what it does not

Compared, because these must be identical:

| field | the joint it guards |
|---|---|
| `score` | the five weights, the +0.25 combo penalty, the ×1.3 urgency multiplier, both `min(1.0)` caps, the trust table, the final scaling formula |
| `band` | the 0.3 / 0.6 boundaries |
| `factors[].category` | which pattern families fire, and in what order |
| `factors[].matches` | the regex dialects themselves, match ordering, dedupe, and the per-family slice caps (6/5/5/4/4) |
| `governing_parameters` | the extracted list and its order |
| `verification_step_count` | the step-construction branches |

Not compared, because these may legitimately differ:

- **The band's name.** Python says `severity` (low/moderate/high); the port
  still says `recommendation` (proceed/verify/stop), because it has not been
  ported past the detection/enforcement split (issue #2). The *boundary* is the
  invariant; the vocabulary is not. Comparing labels would have forced a
  cosmetic rename to satisfy a test.
- **`reasoning` prose.** Presentation.
- **Policy.** The port has no policy layer yet. Parity here is about the
  assessor, and claiming more would be false advertising.

## Why the vectors look the way they do

One vector per joint, not one per scenario. There is a case for every source in
the trust table including an unlisted one (to pin the 0.3 fallback), a case for
every individual regex in all five families, cases that isolate the combo
penalty and the urgency multiplier, cases that saturate every family at once to
exercise both caps, cases that overflow the slice limits, a dedupe case, and
Unicode cases.

The Unicode ones are not padding. They are why this harness exists:

```
unicode-word-boundary
   oracle: ["1.2.3", "2.0.0", "café@1.2.3", "naïve@2.0.0"]
   port:   ["1.2.3", "2.0.0", "ve@2.0.0"]
```

JavaScript's `\w` is ASCII-only; Python's is not. `café@1.2.3` was a governing
parameter to the oracle and invisible to the port — a non-ASCII character in a
package name was an evasion. Fixed by making the port's pattern Unicode-aware,
found on the harness's first run, and unfindable by reading either file alone.

## Adding a vector

Append to `vectors.jsonl`, regenerate the golden, re-run the comparison. A new
vector that immediately disagrees is a finding, not a bug in the harness — that
is what it is for.
