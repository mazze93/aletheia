# Decision Log — aletheia

Format: date · decision · why · how to reverse. Append-only. If a decision
proves wrong, append a reversal entry; never edit an earlier one.

`SECURITY.md` states the posture and the known gaps. GitHub issues track open
work. This file records the choices — especially the ones where a reasonable
person would have gone the other way, and the ones made *between* commits where
the reasoning would otherwise be lost.

---

- **2026-08-15 · Opened this log, late.** The Unicode findings below were made,
  acted on, and nearly committed while living only in a chat transcript, in
  docstrings, and in a job temp directory that is deleted when the job ends.
  Mazze asked, fairly, where observations were being written down and how they
  could follow along and contribute. The honest answer was: nowhere durable.
  A security tool whose findings exist only in one agent's message stream has
  the same defect as a compiled wiki nobody can contest — the reason
  `palimpsest` exists. Started here so the record is arguable.
  *Reverse:* delete `docs/journal/`; keep issues as the only trail.

- **2026-08-15 · The Python assessor is the oracle; the TypeScript port is
  subordinate.** Ported wholesale from `cognitive/stratum`, which pairs a Python
  semantics reference with a TypeScript core and settles disputes the same way,
  rather than inventing a scheme. The asymmetry is the whole value: two peers
  can argue forever, and only an oracle makes a divergence *decidable*. It also
  gives a rule for intentional change — alter the oracle, regenerate the golden,
  then make the port agree. *Reverse:* declare them peers and compare without a
  golden; expect every future disagreement to require a judgment call.

- **2026-08-15 · Parity compares a projection, not the full assessment.**
  Included: score, band, which families fired, matched strings, match order,
  slice caps, governing parameters, verification-step count. Excluded: the
  band's *label* and the `reasoning` prose. Python says `severity`
  (low/moderate/high); the port still says `recommendation`
  (proceed/verify/stop) because it has not been ported past the
  detection/enforcement split (#2). The boundary is the invariant; the
  vocabulary is not. Comparing labels would have forced a cosmetic rename purely
  to satisfy a test — the tail wagging the dog.
  *Reverse:* add `label` to the projection in `parity/emit.py` and `emit.ts`.

- **2026-08-15 · Fixed the first Unicode divergence in the port immediately;
  quarantined the second class in the oracle instead.** Inconsistent on its
  face, so the reasoning matters.

  The first (`café@1.2.3` invisible to the port) was **one pattern**, the port
  was **clearly wrong** against an authoritative oracle, and the fix was
  surgical — a Unicode-aware character class plus a lookbehind replacing a `\b`
  whose JS definition is ASCII-bound.

  The second is **eleven vectors across every family**, and it is the *oracle*
  that is blind: `criticalé` scores 0.0 where the port matches. Fixing it means
  retuning twelve regexes in two dialects, and the last time detection was tuned
  for the loud shape it produced the false positives that forced the shadow-mode
  refactor. Any fix has to keep the six must-not-block regressions green in
  enforce mode. That is design work, not CI plumbing, and slipping it into a
  commit labelled "ci:" would have buried a real security change inside an
  infrastructure diff. Tracked as #3.
  *Reverse:* drop the `known_divergence` flags from `parity/vectors.jsonl` and
  let CI go red until the regexes are reconciled.

- **2026-08-15 · The quarantine asserts continued failure.** A flagged vector
  that starts *agreeing* fails the build with an instruction to close the issue
  and remove the flag. Same discipline as `tests/test_evals.py` for the known
  false negative. A quarantine that silently absorbs a fix is just a slower way
  of not noticing — and an allowlist that only ever grows is how a gate becomes
  decorative. *Reverse:* `continue` past known divergences in
  `parity/compare.py` without the `healed` check.

- **2026-08-15 · Corrected a claim mid-session: Python needs no `\p{L}`.**
  It was suggested that Python's `re` is ASCII-bound by default and that the fix
  had used Unicode property escapes on the Python side. Both are wrong, and the
  correction changes the remediation: Python's `\w`/`\b` are Unicode-aware by
  default for `str` patterns, and `re` has no `\p{L}` support at all (that is
  the third-party `regex` module). The `\p{L}\p{N}` escapes went into the
  **TypeScript** patterns. Recorded because the wrong version of this fact
  points the audit at the wrong file.

- **2026-08-15 · Vectors are one-per-joint, not one-per-scenario.** The corpus
  pins each individual regex, each source in the trust table including an
  unlisted one (to fix the 0.3 fallback), the combo penalty and urgency
  multiplier in isolation, both `min(1.0)` caps via a saturating case, the slice
  limits via overflow, dedupe, and Unicode. Scenario-shaped vectors would
  exercise the same joints repeatedly and leave others untouched, which is how a
  corpus grows large and proves little.

- **2026-08-15 · Wired only `PostToolUse` on `WebSearch|WebFetch`, in shadow
  mode, from `~/.claude/tools/aletheia`.** The runtime install deliberately does
  not live at `~/Projects/tools/aletheia`: that path still holds the old
  in-container copy until the extraction PR merges, and a hook pointing at a
  missing script errors on every search. `~/.claude/` already hosts the other
  hook scripts. Two copies is a drift risk worth consolidating once the PR
  lands. *Reverse:* re-point the hook command in `~/.claude/settings.json`.

- **2026-08-15 · Colocated jujutsu, and named bookmarks for humans.**
  `jj git init --colocate` in the runtime clone, so jj and git operate on the
  same repo and either can drive. Identity set to match the git one
  (`Mazze LeCzzare <mazze@mazzeleczzare.com>`); the working copy's author was
  empty at colocation time and was corrected with `jj metaedit --update-author`,
  which is worth knowing because jj only applies a new identity to *future*
  commits and will otherwise silently author as ` <>`.

  **Bookmark naming is a convention, not a default.** Left alone, jj pushes
  anonymous changes to bookmarks like `push-wxryvkvtnpql` — a name that tells a
  reviewer nothing and is impossible to say out loud. Two rules:

  - `git.push-bookmark-prefix` is `mazze/`, not `push-`, so anything
    auto-created is at least attributable.
  - Prefer creating the bookmark explicitly and descriptively before pushing:
    `jj bookmark create fix/unicode-word-boundary -r @`. The same
    `kind/short-description` shape the git branches already use
    (`extract/aletheia`, `fix/aletheia-npm-alerts`, `map/register-palimpsest`),
    so the two tools produce names that look like each other rather than like
    two different projects.

  *Reverse:* `rm -rf .jj` leaves the git repo untouched and complete —
  colocation adds, it does not convert.

- **2026-08-16 · Replaced `\b` with an explicit boundary policy in both
  implementations, rather than patching the eleven fixtures that exposed it.**
  Issue #3 was not a regex bug; it was security semantics resting on a dialect
  default. `boundary.py` / `boundary.ts` now state the rule — *match a keyword
  unless it is embedded in a larger ASCII identifier; adjacent Unicode letters
  do not suppress it* — and all 27 patterns are built on it.

  Chose an ASCII-identifier rule over a Unicode-aware word-boundary helper such
  as `(?<![^\W\d_])`. The ASCII form says what the detector means, ports
  cleanly, and avoids implementing an ASCII-identifier rule by way of Python's
  Unicode behaviour. Verified it discriminates rather than merely matching more:
  `criticalé` matches, `hypercritical` and `critical_path` still do not, so the
  false-negative class closed without opening a false-positive one — which
  matters, because false positives are what forced shadow mode.
  *Reverse:* the patterns are one `bounded()` call each; unwrapping restores
  `\b` semantics and reopens #3.

- **2026-08-16 · Generalised the fix into an invariant, because fixing fixtures
  fixes fixtures.** `tests/test_boundary_mutations.py` asserts that **no
  Unicode-only mutation of a detection atom may lower the assessed risk**, over
  651 generated cases: 21 atoms × letters from eight scripts × combining marks,
  ZWSP/ZWNJ/ZWJ, RLO and BOM, at both boundaries. The format characters are kept
  as *negative controls* — they did not diverge originally, and a control that
  starts failing is information.

  Also proved the tests would have failed before the fix rather than assuming
  it: the old `\b` patterns are blind to `criticalé`, `écritical`, `criticalЖ`
  and `critical中`; the new ones are not. A detector never made to fail is not
  verified.

- **2026-08-16 · Aligned Python's `\S` to ECMAScript's over U+FEFF.** The
  mutation corpus found a second dialect split the 69 hand-written vectors had
  missed: ECMAScript's WhiteSpace production includes U+FEFF, Python's `\s` does
  not, so `npm install foo` captured a trailing BOM in the oracle and not in the
  port. Same detection, different *extent*. Followed the oracle rule — change
  the oracle, regenerate, then make the port agree — even though here the port's
  reading was the better one, because `governing_parameters` is what a human
  verifies at a registry and an invisible trailing character makes that check
  fail silently. *Reverse:* `NOT_SPACE` in `boundary.py`.

- **2026-08-16 · Made the class un-reopenable, not merely closed.**
  `tests/test_boundary_inventory.py` fails the build if `\b` or `\B` returns to
  either assessor, and requires any `\w` to carry an allowlist entry naming the
  port's equivalent. Without it the next pattern written with `\b` would reopen
  the family silently, and parity would only catch it if someone happened to add
  a vector for that exact token.

- **2026-08-16 · Declined, for now, to add raw input and match spans to the
  audit log.** It would make a future evasion far more explainable, and it would
  turn the audit into a plaintext archive of everything the agent read —
  directly against the MAX-posture reason the log stores hashes. Left on the
  pre-enforcement checklist in `SECURITY.md` as an open tension rather than
  decided quietly in either direction. Mazze's call: the trade is a policy
  question, not an engineering one.

- **2026-08-16 · REVERSAL of the 2026-08-15 "Python assessor is the oracle"
  entry.** That entry said the asymmetry made divergences *decidable*: change
  the oracle, regenerate, make the port agree. The U+FEFF incident the same day
  showed the flaw, and I described that incident in the oracle's own vocabulary
  rather than noticing the contradiction — I wrote "followed the oracle rule to
  fix it… even though here the port's reading was the better one," which is a
  sentence that refutes itself.

  If the port can be right, the reference is not an authority. Parity is a
  **drift detector**: it proves the implementations disagree and says nothing
  about which is correct. Resolution is a policy decision, recorded before
  either side is changed. Python keeps a narrower, mechanical role — the source
  the goldens are generated from, so regeneration is unambiguous.

  Corrected in `parity/compare.py`'s failure output (which was instructing
  readers to conform to the reference), `parity/README.md`, `parity/emit.py`,
  and `assess.py`'s docstring. The compare.py text mattered most: it is what a
  future reader sees at the moment they are deciding how to resolve a
  divergence.
  *Reverse:* restore "the oracle is authoritative" and accept that a correct
  port must be broken to match an incorrect reference.

- **2026-08-16 · Added a hook-level enforce-mode regression, because every
  other test calls functions.** `tests/test_hook_enforce.py` runs the actual
  shell adapter with a real payload on stdin and reads the audit log it writes.
  Shadow mode proves *detection*; it does not prove that a detected payload
  stops a tool call, which is the only property that matters once
  `ALETHEIA_MODE=enforce` is set.

  Its fixture is the issue-3 evasion rather than a plain injection: every
  keyword decorated with a non-ASCII letter at its boundary. Under the pre-fix
  patterns exactly one family matched (`high-severity`) and it scored below the
  verify threshold; under the boundary policy it scores 0.88 and stops. So the
  test fails if the boundary policy is ever unwound, regardless of what the unit
  tests report. Also covers the adapter failing *open* when the install is
  missing — a security hook that breaks the agent when its own path is wrong is
  worse than no hook.

- **2026-08-16 · Issue #1 confirmed as an active pre-enforcement blocker, not
  a background gap.** Measured rather than assumed: `incident-devserver.txt`
  scores 0.26 from `web_fetch` and 0.21 from `mcp_tool`, and both resolve to
  **`proceed`** under `ENFORCE`. So a labelled incident would pass a live gate.
  Promoted in `SECURITY.md` from "known gap" to a checklist item that blocks
  turning enforcement on.
- **2026-09-06 · Append-only ledgers merge by union; the bottom-append
  convention is what makes that safe.** Mazze's point, from the Anthropic
  commerce-agent blueprint: an append-only ledger should be written at the
  bottom, not the top. Correct, and worth stating why it is more than tidiness.

  Bottom-appending alone does not stop git conflicting — two branches that both
  append still touch the same region. What it does is make `merge=union`
  *semantically safe*: union concatenates hunks in file order, so an appended
  ledger stays chronological while a prepended one interleaves into nonsense.
  Convention and merge driver are two halves of one mechanism, and we had only
  the first.

  Verified against a real divergence rather than asserted. `tools/stele` sits 3
  ahead / 20 behind with add/add conflicts on all three journal files. With
  `docs/journal/DECISIONS.md merge=union`, DECISIONS.md auto-merged — zero
  conflict markers, all 20 entries from both sides preserved — while PLAN.md
  and CHECKPOINT.md still conflicted, which is the correct outcome: they are
  rewritten projections, not ledgers, and union would duplicate checklist items
  and resurrect ticked boxes. The rule discriminates rather than silencing
  everything, which is the same standard applied to apatea's transformations.

  All four DECISIONS.md files in the fleet were already ascending, so no ledger
  needed reordering — only the driver was missing.
  *Reverse:* delete `.gitattributes`; conflicts return, nothing is lost.
