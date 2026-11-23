"""Known-failure monotonicity — the gate's own alarm for its own memory.

`tests/test_evals.py` is the never-silent-green alarm: a known failure that
starts *passing* fails the suite. It cannot see the other half — a known
failure that *vanishes* (line deleted, flag flipped, expect_action weakened)
with the gap still open. The detector still cannot stop the case, but the
record that it cannot is gone, and nothing fails.

This is that other half. It compares the known-failure declarations in
`expected.jsonl` against a base (git) and fails when a declaration was removed
or weakened *without* the gap actually closing. Closure is real only if the
detector now stops the case — the same fact `test_corpus` asserts from the
opposite direction. So a gap that genuinely closes (alarm fires, flag removed)
passes here; a flag removed while the case still does not stop fails here.

Not a generate-and-diff guard like `parity/unicode_boundary_mutations.py` —
that pattern needs an independent generator, and `expected.jsonl` is authored
(note prose is not derivable). The memory here is git, not regeneration.

Run:
    PYTHONPATH=src python3 evals/check_known_failures.py --base-ref <git-ref>
    PYTHONPATH=src python3 evals/check_known_failures.py --current-only

Exits 0 when the known-failure set is honest; 1 when one silently vanished;
2 on usage error.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
EXPECTED = HERE / "expected.jsonl"
REPO_ROOT = HERE.parent

sys.path.insert(0, str(REPO_ROOT / "src"))
from aletheia.assess import assess  # noqa: E402
from aletheia.policy import decide, ENFORCE  # noqa: E402
from aletheia.provenance import build  # noqa: E402


def load_cases(path: pathlib.Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def is_kf(case: dict) -> bool:
    return bool(case.get("expect_known_failure"))


def declared_stop(case: dict) -> bool:
    """A kf declaration is `expect_known_failure: true` AND `expect_action: stop`."""
    return is_kf(case) and case.get("expect_action") == "stop"


# --- invariants of the current file (no memory needed) ---------------------

def current_invariants(cases: list[dict]) -> list[str]:
    problems = []
    seen = set()
    for case in cases:
        f = case.get("file")
        if not f:
            problems.append("a case has no `file` field")
            continue
        if f in seen:
            problems.append(f"{f}: declared more than once in expected.jsonl")
        seen.add(f)
        if not (HERE / f).is_file():
            problems.append(f"{f}: referenced in expected.jsonl but missing from disk")
        if is_kf(case) and case.get("expect_action") != "stop":
            problems.append(
                f"{f}: expect_known_failure is true but expect_action is "
                f"{case.get('expect_action')!r}, not 'stop' — a known failure "
                "declares that the gate does not stop it"
            )
    return problems


# --- monotonicity vs a base (the shrinkage detector) ------------------------

def base_cases(ref: str) -> list[dict] | None:
    """expected.jsonl at a git ref; None if the ref is unresolvable."""
    try:
        out = subprocess.run(
            ["git", "show", f"{ref}:evals/expected.jsonl"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        )
    except subprocess.CalledProcessError:
        return None
    return [json.loads(l) for l in out.stdout.splitlines() if l.strip()]


def check_monotonic(head: list[dict], base: list[dict]) -> list[str]:
    problems = []
    closures = []
    head_by_file = {c["file"]: c for c in head}
    for b in base:
        if not declared_stop(b):
            continue  # only known failures carry the monotonicity guarantee
        f = b["file"]
        h = head_by_file.get(f)
        if h is not None and declared_stop(h):
            continue  # still declared — monotonic, fine
        # Declaration removed or weakened. Is the gap actually closed?
        content_path = HERE / f
        if not content_path.is_file():
            problems.append(
                f"{f}: known-failure case removed from expected.jsonl and its "
                "content file deleted. Known failures may not be silently "
                "deleted — close the gap (teach the gate to stop it) or "
                "tombstone with a recorded decision."
            )
            continue
        origin = (h or b).get("origin", "web_search")
        content = content_path.read_text(encoding="utf-8")
        event = build(content=content, origin=origin, event="PostToolUse")
        a = assess(content, event.origin)
        action = decide(event, a.injection_risk_score, mode=ENFORCE,
                        reasoning=a.reasoning).action
        if action == "stop":
            closures.append(
                f"{f}: known failure closed — detector now stops it "
                "(test_corpus's alarm, seen from this side)."
            )
        else:
            problems.append(
                f"{f}: known-failure declaration removed or weakened, but the "
                f"detector still does not stop it (action={action}). The gap is "
                "open. Restore the declaration, or teach the gate to stop it — "
                "removing the flag while the case still proceeds is how a "
                "security tool forgets what it cannot do."
            )
    for c in closures:
        print("  closure acknowledged: " + c)
    return problems


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--base-ref", help="git ref whose expected.jsonl is the memory")
    g.add_argument("--current-only", action="store_true",
                   help="check current-file invariants only")
    args = ap.parse_args(argv)

    cases = load_cases(EXPECTED)
    problems = current_invariants(cases)
    monotonic = "(not checked)"

    if not args.current_only and args.base_ref:
        base = base_cases(args.base_ref)
        if base is None:
            print(f"::warning::base ref {args.base_ref!r} unresolvable — "
                  "monotonicity NOT checked; invariants only.")
        else:
            problems.extend(check_monotonic(cases, base))
            monotonic = f"monotonic vs {args.base_ref}"

    if problems:
        print("::error::known-failure memory is not honest:")
        for p in problems:
            print("  - " + p)
        return 1

    n_kf = sum(1 for c in cases if is_kf(c))
    print(f"known-failure memory OK — {n_kf} known failure(s); {monotonic}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
