# Security advisory: Unicode boundary evasion in cross-runtime AI-agent security assessors

**Status:** remediated in-tree (boundary helpers + CI inventory + mutation corpus)  
**Component:** Aletheia Python and TypeScript assessors  
**Date:** 2026-11-03 (formal write-up; fix landed earlier in the boundary work)  
**CVE:** not claimed — coordinated product advisory / case study only

## Executive summary

Aletheia identified and corrected a cross-runtime lexical-boundary discrepancy: Unicode letters adjacent to ASCII security keywords could suppress Python detection while not suppressing TypeScript detection (and, in related cases, the reverse). That false negative affected risk scoring for untrusted agent-tool outputs and could allow selected adversarial content an undeservedly low score.

Remediation replaces runtime-default `\b` / `\w` semantics with an explicit ASCII-identifier boundary policy in both runtimes, backed by mutation testing, parity fixtures, CI inventory controls that reject `\b`/`\B` reintroduction, and hook-level enforcement evidence. See `SECURITY.md` (“Lexical boundaries are policy, not defaults”) and `src/aletheia/boundary.py` / `typescript/src/boundary.ts`.

## Affected component and scope

- **In scope:** Python (`src/aletheia/assess.py` + `boundary.py`) and TypeScript (`typescript/src/assess.ts` + `boundary.ts`) assessors; patterns that formerly relied on `\b`.
- **Out of scope as “closed by this advisory”:** homoglyph substitution, encoded payloads, semantic paraphrase, quiet structural injection, register/soft-costume gaps, and any currently open known-failure evals.

## Impact

Risk-scoring **false negatives** for Unicode-adjacent detection terms. Real impact depends on:

- score thresholds and provenance weighting in the integration,
- whether the hook is in **shadow** or **enforce** mode,
- whether the missed token was the only signal raising the score.

This is not claimed as a universal prompt-injection bypass.

## Technical root cause

`\b` means “a transition between `\w` and `\W`.” Python `str` regex `\w` is Unicode-aware; ECMAScript `\w` is ASCII-only. Security semantics were resting on that dialect split, so neither runtime was a reliable oracle for the other. Parity is a **drift alarm**, not a semantic judge.

Related extent bugs (e.g. U+FEFF vs `\S+`) and case-folding of the boundary class under global `i` are documented in `SECURITY.md`; they are part of the same class of “defaults mistaken for policy.”

## Proof of concept (current tree)

Verified 2026-11-03 against `PYTHONPATH=src` `assess(..., "web_fetch")`:

| Input | Urgency/`critical` detected? |
|---|---|
| `criticalé` | yes (score &gt; 0) |
| `écritical` | yes |
| `criticalЖ` | yes |
| `critical中` | yes |
| `hypercritical` | no (0.0) — ASCII identifier embed |
| `critical_path` | no (0.0) — ASCII identifier embed |

Pre-fix, the Unicode-adjacent rows were the false-negative class this advisory names.

## Remediation

- Explicit boundary helpers: `bounded()` / `bounded_caseless()` (Python) and TypeScript equivalents.
- All relevant detection patterns built through those helpers — not raw `\b`.
- Case-insensitive keyword matching without folding the boundary class (`bounded_caseless`).

## Validation

- Boundary mutation corpus and parity fixtures (see `parity/`, `tests/test_boundary_mutations.py`).
- CI inventory: `tests/test_boundary_inventory.py` fails on `\b`/`\B` reintroduction and illegal ignore-case + boundary-class combinations.
- Hook-level exercises in shadow/enforce as described in project docs — an `assess()` score alone is not enforcement-layer proof.

## Limitations (remaining perimeter)

Homoglyphs, encoded payloads, semantic paraphrase, quiet structural injection, and register-gap costumes remain open classes. They need separate instruments — not a silent claim that this advisory closed them.

## Deployment guidance

Prefer **shadow** mode until pre-enforcement blockers are closed or formally accepted by an accountable owner. Do not treat “Unicode boundary closed” as permission to enforce without reading the current known-failure eval list.

## Related

- Method: [`class-closure-checklist.md`](./class-closure-checklist.md)
- Paradigm essay (recovered): [`Class_Closure_Threat_Response.md`](./Class_Closure_Threat_Response.md)
- Living posture: `SECURITY.md`
