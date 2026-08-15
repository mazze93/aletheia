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
