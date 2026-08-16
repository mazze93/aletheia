"""Compare the port's projection against the oracle's golden, joint by joint.

    python3 parity/compare.py parity/assess.golden.json /tmp/ts.json

Exits 0 when they agree, 1 when they do not, and prints a table naming the
vector, the field, and both values — because "parity failed" is useless and
"vector `combo-gov-and-prescriptive`: score 0.82 vs 0.57" tells you which
weight someone changed.

The mirrored joints this covers, which is the whole point of comparing a
projection rather than a score:

    score          weights, combo penalty, urgency multiplier, the min(1.0)
                   caps, the trust table, and the final scaling formula
    band           the 0.3 / 0.6 boundaries, named neutrally so the two
                   vocabularies (severity vs recommendation) may differ
    factors        which pattern families fired, in which order
    matches        the regex dialects themselves, their ordering, their
                   dedupe behaviour, and the per-family slice caps
    governing_parameters   the list and its order
    verification_step_count   the step-construction branches
"""
from __future__ import annotations

import json
import pathlib
import sys


def canonical(x):
    if isinstance(x, list):
        return [canonical(i) for i in x]
    if isinstance(x, dict):
        return {k: canonical(x[k]) for k in sorted(x)}
    return x


def known_divergences(vectors_path) -> dict:
    """Vectors explicitly recorded as diverging, with the issue that tracks them.

    A flagged vector is *asserted to still diverge*. If one starts agreeing, the
    build fails and says so — the same discipline tests/test_evals.py applies to
    the known false negative. A quarantine that silently absorbs a fix is just a
    slower way of not noticing.
    """
    out = {}
    with open(vectors_path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            case = json.loads(line)
            if case.get("known_divergence"):
                out[case["id"]] = case["known_divergence"]
    return out


def diffs(oracle: dict, port: dict) -> list[str]:
    out: list[str] = []

    if oracle.get("vector_count") != port.get("vector_count"):
        out.append(
            f"vector_count: oracle {oracle.get('vector_count')} != "
            f"port {port.get('vector_count')}"
        )

    by_id_o = {c["id"]: c for c in oracle.get("cases", [])}
    by_id_p = {c["id"]: c for c in port.get("cases", [])}

    for missing in sorted(set(by_id_o) - set(by_id_p)):
        out.append(f"{missing}: present in oracle, absent from port")
    for extra in sorted(set(by_id_p) - set(by_id_o)):
        out.append(f"{extra}: present in port, absent from oracle")

    known = getattr(diffs, "known", {})
    healed: list[str] = []

    for vid in [c["id"] for c in oracle.get("cases", []) if c["id"] in by_id_p]:
        o, p = canonical(by_id_o[vid]), canonical(by_id_p[vid])
        agrees = o == p

        if vid in known:
            if agrees:
                healed.append(
                    f"{vid}: known divergence ({known[vid]}) now AGREES — "
                    "remove known_divergence from vectors.jsonl and close the issue"
                )
            continue  # expected to differ; not a build failure

        if agrees:
            continue
        for field in sorted(set(o) | set(p)):
            ov, pv = o.get(field), p.get(field)
            if ov == pv:
                continue
            out.append(f"{vid}  {field}\n     oracle: {json.dumps(ov, ensure_ascii=False)}"
                       f"\n     port:   {json.dumps(pv, ensure_ascii=False)}")
    return out + healed


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    oracle = json.loads(open(argv[1], encoding="utf-8").read())
    port = json.loads(open(argv[2], encoding="utf-8").read())

    # Which corpus produced this golden. Stated by the emitter rather than
    # assumed, so a second corpus cannot silently inherit the first one's
    # quarantine flags.
    corpus_name = oracle.get("_corpus", "vectors.jsonl")
    corpus = pathlib.Path(argv[1]).resolve().parent / corpus_name
    diffs.known = known_divergences(corpus) if corpus.is_file() else {}

    found = diffs(oracle, port)
    if not found:
        n = oracle.get("vector_count", "?")
        k = len(diffs.known)
        note = f", {k} known divergence(s) quarantined" if k else ""
        print(f"parity OK — {n} vectors, TypeScript matches the Python oracle{note}")
        if k:
            print("  quarantined: " + ", ".join(sorted(diffs.known)))
        return 0

    print(f"PARITY BROKEN — {len(found)} divergence(s)\n")
    print("The Python oracle (src/aletheia/assess.py) is authoritative.")
    print("Where they disagree, the TypeScript port is wrong.\n")
    for d in found:
        print(f"  {d}")
    print(
        "\nIf you changed a weight, a threshold, or a pattern in one language, "
        "change it in the other.\nIf the change is intentional and the port is "
        "now correct, change the oracle first,\nthen regenerate: "
        "python3 parity/emit.py > parity/assess.golden.json"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
