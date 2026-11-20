---
title: Class-Closure Threat Response
status: recovered
recovered_from: archive/rescue/structured-governing-params-2026-09-16
recovered_commit: 4ed24bb
note: >
  This advisory was on the structured-governing-params rescue tip but never
  landed with PR #4. Recovered 2026-11-03 after muster-triage residual check
  flagged it as stranded tip-only content. Substance preserved. Residual
  Perplexity export chrome removed 2026-11-20; rewrite same day for
  presentation clarity. Mutation corpus count updated from the recovered
  draft's 651 to the current 819 (CASEFOLD_EDGES expansion), matching
  SECURITY.md and parity/mutations.jsonl.
---

# Class-Closure Threat Response

**A method for turning a security finding into a closed failure class — with
evidence that the class cannot silently recur.**

Aletheia’s Unicode-boundary incident is the concrete case. The durable output
is not a patch note about `\b`. It is a repeatable, evidence-led threat-response
paradigm for AI-agent security controls: find the violated assumption, replace
it with an explicit policy, prove the class closed, and publish what remains
open.

This document is two layers in one place:

1. **Case study / security advisory** — Unicode boundary evasion in
   cross-runtime agent security assessors.
2. **Operating model** — Class-Closure Threat Response: from symptom to
   invariant.

It aligns with Secure by Design’s emphasis on ownership, transparency, and
reducing systemic vulnerability classes rather than merely repairing individual
defects.[^1][^2]

---

## 1. What went wrong

Aletheia scores untrusted agent-tool output for injection risk. Several of its
detectors used regex word boundaries (`\b`) as if they were a portable
lexical policy.

They are not. `\b` means “a transition between `\w` and `\W`,” and Python and
JavaScript disagree about `\w`: Python’s `str` patterns are Unicode-aware;
ECMAScript’s default `\w` is ASCII-only. Security semantics were resting on
that dialect split.

Two evasions appeared in opposite directions. Neither runtime was reliably the
correct one:

| Payload | Python | TypeScript |
| --- | --- | --- |
| `café@1.2.3` | extracted as a governing parameter | **invisible** to extraction |
| `criticalé` | **score 0.0** (miss) | matched |

A Unicode letter next to an ASCII security keyword could suppress Python
detection while TypeScript still fired — a false negative in the live assessor
path. Impact depends on score threshold, provenance weighting, and whether the
integration is in shadow or enforce mode. The failure mode was real and
reproducible; it was not a universal prompt-injection bypass.

---

## 2. The governing principle

> A security finding is not resolved when the reported payload stops working.
> It is resolved, within a stated scope, when the failure-producing assumption
> is replaced by an explicit policy and the system can demonstrate that the
> class cannot silently recur.

That is **class closure**. Patching the string is necessary. Closing the class
is the work.

---

## 3. The nine-stage loop

Applied to Aletheia’s boundary work, then stated as a general rule:

| # | Stage | What happened in Aletheia | General rule |
| ---: | --- | --- | --- |
| 1 | Establish the exploit | Unicode adjacent to security terms caused the Python detector to miss otherwise recognizable risk signals | Demonstrate the behavior in the real execution path, not only in a synthetic unit test |
| 2 | Find the violated assumption | `\b` was treated as a portable lexical boundary despite different Unicode semantics in Python and ECMAScript | Identify the abstraction or default that made the exploit possible |
| 3 | State the policy | Match a security keyword unless it is embedded inside a larger ASCII identifier; Unicode adjacency does not suppress detection | Replace implicit runtime behavior with human-reviewable semantics |
| 4 | Repair every implementation | Dedicated boundary helpers in Python and TypeScript replaced direct dependence on `\b` | Implement the policy consistently across every relevant boundary |
| 5 | Generate adversarial variants | 819 Unicode boundary mutations (21 detection atoms × scripts, controls, and case-fold edges) | Test the *transformation space*, not only known strings |
| 6 | Encode an invariant | No Unicode-only mutation may lower assessed risk | Express the security property in a machine-checkable form |
| 7 | Block regression structurally | CI rejects `\b`/`\B` reintroduction, global ignore-case on bounded patterns, and stale mutation corpora | Prevent re-entry of the underlying unsafe primitive or process |
| 8 | Prove system behavior | Hook exercised in shadow and enforce modes, including audit output | Verify the control at the layer where security consequences occur |
| 9 | Preserve the remainder | Structural injection, homoglyphs, paraphrase, and audit-retention tradeoffs stay explicitly open | Separate demonstrated closure from the unresolved threat perimeter |

This follows the same logic NIST foregrounds for incident response: lessons
learned and root-cause analysis should feed continuous improvement, not sit
only in an after-action report.[^3][^4]

---

## 4. Why this is more than testing

The novel element is the distinction among **policy**, **reference
implementation**, and **evidence**.

### Parity is a drift alarm, not a semantic judge

A difference between Python and TypeScript proves disagreement. It does not
establish which side is right.

Aletheia’s U+FEFF finding made this concrete. ECMAScript treats U+FEFF as
whitespace; Python did not. Extraction via `\S+` therefore captured a different
*extent*. Python had been treated as the oracle for cross-runtime parity — but
the Python behavior was not necessarily correct. An invisible BOM retained in a
governing parameter would make registry verification fail silently. The correct
move was not “make TypeScript match Python,” but “write down what extraction
should mean, then conform both implementations.”

### Generated adversarial corpora are executable policy tests

Hand-written vectors catch known bugs. A generated corpus exposes mutation
families and makes coverage shrinkage detectable. Aletheia’s corpus grew from
651 cases to 819 when case-fold edges (Kelvin sign, long s, dotted/dotless i)
were added — a second evasion that lived *inside* the first fix, invisible to
parity because both runtimes were wrong together.

### An enforcement claim requires enforcement-layer evidence

A high score from `assess()` is not proof that an agent hook stops, logs, and
safely handles the same payload in its actual runtime. Class closure includes
exercising the adapter (exit codes, audit records, shadow vs enforce) at the
layer where consequences occur.

These principles transfer to other agentic mismatch surfaces: SDK vs gateway
policy, browser vs server parsing, Unicode normalization, shell quoting, URL
parsing, structured-output extraction, and provider-specific interpretations of
the same data.

---

## 5. Security advisory: Unicode boundary evasion

**Title.** Security advisory: Unicode boundary evasion in cross-runtime
AI-agent security assessors

### Executive summary

Aletheia identified and corrected a cross-runtime lexical-boundary discrepancy
in which Unicode letters adjacent to ASCII security keywords could suppress
Python detection while not suppressing TypeScript detection. The issue affected
risk scoring for untrusted agent-tool outputs and could permit selected
adversarial content to receive an undeservedly low score. Remediation replaces
runtime-default word-boundary semantics with an explicit ASCII-identifier
boundary policy, backed by mutation testing, parity checks, CI inventory
controls, and hook-level enforcement tests.

### Affected component and scope

- Python and TypeScript assessor implementations (`assess`), especially
  patterns formerly based on `\b` / `\B` / `\w`.
- Boundary helpers: `src/aletheia/boundary.py`, `typescript/src/boundary.ts`.
- Out of scope for this class: policy, provenance, and audit layers on the
  TypeScript port (still incomplete — see known gaps).

### Impact

A risk-scoring false negative for Unicode-adjacent detection terms. Severity
depends on threshold (0.3 verify / 0.6 stop), provenance weighting, and whether
the integration is in shadow or enforce mode. This is a detector-integrity
issue, not a claim of remote code execution by itself.

### Technical root cause

Python `str` regex handling of `\w` is Unicode-aware; ECMAScript `\w` defaults
differ. Therefore `\b` does not represent a shared application-level lexical
policy. A later related root cause: compiling the ASCII boundary class with a
global ignore-case flag folds the class itself, accepting letters that case-fold
onto ASCII (e.g. U+212A Kelvin → `K`).

### Proof of concept (illustrative)

| Should match (Unicode adjacency) | Should not match (ASCII embedding) |
| --- | --- |
| `criticalé`, `écritical` | `hypercritical` |
| `criticalЖ`, `critical中` | `critical_path` |

Case-fold edges closed in the same class of work include `criticalK`
(U+212A), `ſcritical` (U+017F), and `criticalİ` / `criticalı`.

### Remediation

1. State policy: match a security keyword unless embedded in a larger ASCII
   identifier; Unicode adjacency does not suppress detection.
2. Implement dedicated boundary helpers; build all relevant patterns through
   them (`bounded_caseless` / `boundedCaseless` where case-insensitive matching
   is required — without folding the boundary class).
3. Pin non-space extraction so U+FEFF cannot change governing-parameter extent
   across runtimes.
4. Inventory `\b` / `\B` / `\w`; reject reintroduction in CI.

### Validation

- 819 generated mutations across both runtimes; corpus regenerable and
  freshness-gated in CI.
- Invariant: no Unicode-only mutation may lower assessed risk.
- Equality/parity fixtures for assessor fields (score, band, factors,
  governing parameters).
- Hook-level enforce-mode regression (adapter exit 2 + audit factors).
- Threshold-edge assertions at the verify/stop boundaries.

### Limitations (this class only)

Homoglyph substitution, encoded payloads, semantic paraphrase, quiet structural
injection, and any currently open low-scoring known case remain out of scope.
Closing the Unicode-boundary class does not close those.

### Deployment guidance

Remain in shadow mode until known pre-enforcement blockers are closed or
formally accepted by an accountable owner. In Aletheia’s current posture, quiet
structural injection (issue #1) and audit match-span retention are the named
open dispositions.

### Disclosure note

Avoid labeling this a “CVE” unless the issue meets applicable product and
coordination criteria. Coordinated disclosure normally involves report
collection, technical validation, mitigation coordination, time for affected
users to apply mitigations, then accurate public disclosure.[^5][^6]

---

## 6. Class-closure checklist

Reusable output — a short method checklist, not an expansive framework:

1. **Reproduce** the exploit through the deployed or deployable path.
2. **Name** the unsafe assumption — not merely the broken test.
3. **Write** the intended security behavior as an explicit policy.
4. **Repair** every implementation that enforces or represents that policy.
5. **Generate** adversarial variants over the relevant transformation space.
6. **Encode** a monotonic or non-bypass invariant where possible.
7. **Gate** unsafe primitives and stale evidence structurally in CI.
8. **Test** the policy at its real enforcement boundary, including telemetry.
9. **Publish** the exact scope of closure and the remaining perimeter.

A finding should create an **instrument**, not merely a patch: a policy object,
a corpus, a test invariant, a CI control, an auditable decision record, and an
explicit statement of what the instrument still cannot see. That preserves
uncertainty while still producing concrete, reviewable action — which is the
point of threat response in agentic software.

---

## 7. Remaining perimeter

Class closure is local. Aletheia’s documented remainder includes:

| Open area | Why it matters |
| --- | --- |
| Quiet structural injection | Structured JSON without urgency/authority/imperative can score below threshold and proceed under enforcement |
| Lexical evasion / paraphrase / homoglyphs | Regex raises cost; it does not raise it to infinity |
| TypeScript stack completeness | Port covers `assess()` parity only; no policy/provenance/audit yet |
| Audit forensics vs retention | Hashes without match spans limit explainability; raw spans would archive plaintext |

Demonstrated closure of the Unicode-boundary class does not imply closure of
these. Naming them is part of the method.

---

## References

[^1]: <https://www.cisa.gov/securebydesign>

[^2]: <https://www.cisa.gov/news-events/news/cisa-us-and-international-partners-announce-updated-secure-design-principles-joint-guide>

[^3]: <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf>

[^4]: <https://csrc.nist.gov/projects/incident-response>

[^5]: <https://www.cisa.gov/resources-tools/programs/coordinated-vulnerability-disclosure-program>

[^6]: <https://www.cisa.gov/resources-tools/resources/establishing-coordinated-vulnerability-disclosure-program-work-security-researchers>

### Further reading

Public documents that informed the recovered draft:

- [CISA / partners: working with security researchers](https://www.cisa.gov/news-events/news/cisa-and-partners-publish-guidance-help-software-manufacturers-and-online-service-providers-work)
- [NSA release on establishing CVD programs](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4546549/nsa-joins-cisa-and-others-in-releasing-the-cybersecurity-information-sheet-esta/)
- [CSI: Secure by Design / Default (PDF)](https://media.defense.gov/2023/Apr/13/2003198917/-1/-1/0/CSI_Secure_by_Design_Default.PDF)
- [CISA vulnerability disclosure policy template](https://www.cisa.gov/vulnerability-disclosure-policy-template)
- [NIST SP 800-61 overview (Netscout)](https://www.netscout.com/what-is/nist-sp-800-61)
- [NIST incident response life cycle (Cynomi)](https://cynomi.com/nist/nist-incident-response-life-cycle-explained/)
- [NIST IR update notes (Inside Privacy)](https://www.insideprivacy.com/cybersecurity-2/nist-publishes-updated-incident-response-recommendations-and-considerations/)
- [CISA Secure by Design principles (handbook)](https://www.securebydesignhandbook.com/docs/quick-start/cisa-sbd-principles)
- [CISA Secure by Design 2026 update (handbook)](https://www.securebydesignhandbook.com/blog/2026/05/12/cisa-secure-by-design-update)
