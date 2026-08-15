"""Aletheia CLI — the entry point a Claude Code hook actually invokes.

    echo '{"hook_event_name":"PostToolUse","tool_name":"WebSearch",...}' | aletheia
    aletheia --source web_search < content.txt
    aletheia --mode enforce            # opt in to blocking; default is shadow

Reads a hook payload (or raw text with `--source`) on stdin, classifies it,
asks the policy layer what that means, records an audit line, prints the
assessment as JSON on stdout, puts human-readable reasoning on stderr, and
exits with the code the policy layer chose.

Default mode is **shadow**: every outcome exits 0. Blocking requires an explicit
`--mode enforce`, because a detector that has never been measured against real
traffic does not know its own false-block rate.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from . import audit, hooks, policy, provenance
from .assess import assess


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aletheia", description=__doc__)
    p.add_argument("--source", default=None,
                   help="origin for raw stdin text (web_search, web_fetch, "
                        "mcp_tool, file, user, clipboard, agent, unclassified)")
    p.add_argument("--mode", choices=[policy.SHADOW, policy.ENFORCE],
                   default=policy.SHADOW,
                   help="shadow (default): record only, always exit 0. "
                        "enforce: blocking decisions block.")
    p.add_argument("--taint", action="append", default=[],
                   help="declare carried taint, e.g. external_instructional_content")
    p.add_argument("--intended-action", default=None,
                   help="the action this content would drive, for the reasoning")
    p.add_argument("--no-audit", action="store_true", help="skip the audit log")
    p.add_argument("--quiet", action="store_true", help="suppress stdout JSON")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    raw = sys.stdin.read()
    if not raw.strip():
        return 0

    payload = None
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict) and parsed.get("hook_event_name"):
            payload = parsed
    except json.JSONDecodeError:
        pass

    if payload is not None:
        event = hooks.to_event(payload, taint=args.taint or None)
        session_id = payload.get("session_id", "")
    else:
        event = provenance.build(
            content=raw,
            origin=args.source or "unclassified",
            event="Manual",
            taint=args.taint,
        )
        session_id = ""

    assessment = assess(event.content, event.origin, args.intended_action)
    decision = policy.decide(event, assessment.injection_risk_score,
                             mode=args.mode, reasoning=assessment.reasoning)

    if not args.no_audit:
        audit.record(event, assessment, decision, session_id=session_id)

    if not args.quiet:
        out = asdict(assessment)
        out["action"] = decision.action
        out["enforced"] = decision.enforced
        out["mode"] = decision.mode
        out["origin"] = event.origin
        out["trust"] = event.trust
        out["taint"] = event.taint
        print(json.dumps(out, indent=2, ensure_ascii=False))

    text = hooks.render(assessment, decision, event)
    if text:
        print(text, file=sys.stderr)

    return decision.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
