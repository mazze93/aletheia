"""Append-only JSONL audit. What she saw, what she scored, what she would do.

Shadow mode is only worth running if it leaves evidence, and this is the
evidence. Every event is recorded with the decision that *would* have been
enforced, so the false-block rate can be measured before anything is allowed to
block.

MAX posture, and the reason this module is separate: **the audit log must not
become a second copy of sensitive content.** Aletheia sits on the channel where
web results, file contents and command text pass. Writing those verbatim would
turn a security tool into a plaintext archive of everything the agent touched.
So the log stores a content *hash* plus the matched feature strings, and the
raw payload never lands on disk unless the operator explicitly opts in.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DEFAULT_LOG = Path.home() / ".claude" / "aletheia" / "audit.jsonl"

# Opt-in only, and named so it cannot be set by accident.
RAW_ENV = "ALETHEIA_AUDIT_RAW"


def content_hash(text: str) -> str:
    return "blake2s:" + hashlib.blake2s(text.encode("utf-8"), digest_size=16).hexdigest()


def log_path() -> Path:
    override = os.environ.get("ALETHEIA_AUDIT_LOG")
    return Path(override) if override else DEFAULT_LOG


def record(event, assessment, decision, session_id: str = "",
           path: Optional[Path] = None) -> dict:
    """Append one event. Returns the record written."""
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "session_id": session_id or os.environ.get("CLAUDE_SESSION_ID", ""),
        "hook_event": event.event,
        "tool": event.tool,
        "origin": event.origin,
        "trust": event.trust,
        "trust_class": event.trust_class,
        "taint": event.taint,
        "score": assessment.injection_risk_score,
        "severity": assessment.severity,
        "features": [
            {"category": f["category"], "matches": f["matches"][:5]}
            for f in assessment.risk_factors
        ],
        "action": decision.action,
        "would_block": decision.would_block,
        "enforced": decision.enforced,
        "mode": decision.mode,
        "content_hash": content_hash(event.content),
        "content_bytes": len(event.content),
    }
    if os.environ.get(RAW_ENV) == "1":
        entry["content"] = event.content

    target = path or log_path()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        # An audit failure must never take down the tool call being audited.
        # A hook that breaks the agent when its disk is full is worse than a
        # hook that silently misses a line.
        pass
    return entry
