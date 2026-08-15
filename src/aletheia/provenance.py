"""Where content came from, and what that entitles it to.

This module exists because of a specific defect. The original hook mapped every
`Bash`/`Edit`/`Write` payload to source `unknown` (trust 0.3), and `unknown` was
treated as *untrusted external content*. An agent-authored command is not
external content — it is the agent acting on the principal's instruction. The
collapse meant a command that merely *talked about* versions urgently scored the
same as a crafted web result, so ordinary remediation work crossed the stop
threshold.

Two corrections live here:

1. **`unclassified` is not `untrusted`.** Unknown provenance is a reason to
   audit and to ask, never a reason to automatically stop. Absence of evidence
   about origin is not evidence of hostile origin.

2. **Taint is carried, not inferred.** If a command derives from external
   content, that fact travels with it explicitly in `taint`. It is never
   re-derived from the presence of words like "critical" or a semver string,
   because those are equally the vocabulary of legitimate security work.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

TRUSTED = "trusted"
SEMI_TRUSTED = "semi_trusted"
UNTRUSTED = "untrusted"
UNCLASSIFIED = "unclassified"

# Trust is about authority to *govern action*, not about correctness.
TRUST = {
    "user": 1.0,          # the principal; what they say governs
    "agent": 0.95,        # the agent acting on the principal's instruction
    "file": 0.9,          # committed, version-controlled
    "mcp_tool": 0.5,      # depends on the tool; can be compromised
    "web_search": 0.2,    # can be crafted — was crafted
    "web_fetch": 0.2,
    "clipboard": 0.1,     # unknown origin, maximum suspicion
    "unclassified": 0.3,  # fail-safe: audit and verify, never auto-stop
}

TRUST_CLASS = {
    "user": TRUSTED,
    "agent": TRUSTED,
    "file": TRUSTED,
    "mcp_tool": SEMI_TRUSTED,
    "web_search": UNTRUSTED,
    "web_fetch": UNTRUSTED,
    "clipboard": UNTRUSTED,
    "unclassified": UNCLASSIFIED,
}

# Tools whose *output* is inbound content from elsewhere.
INBOUND_TOOLS = {
    "WebSearch": "web_search",
    "WebFetch": "web_fetch",
}

# Tools whose *input* the agent authors itself.
AGENT_AUTHORED_TOOLS = frozenset({"Bash", "Edit", "Write", "NotebookEdit", "MultiEdit"})

# Effects that materialise harm. Distinguished from reading, because this is
# where a taint carried from external content actually matters.
DESTRUCTIVE_TOOLS = frozenset({"Bash", "Write", "Edit", "NotebookEdit", "MultiEdit"})
EGRESS_TOOLS = frozenset({"WebFetch", "Bash"})

EXTERNAL_INSTRUCTIONAL = "external_instructional_content"


@dataclass
class Event:
    """A normalized envelope. The core consumes this; adapters produce it."""

    content: str
    origin: str
    event: str = ""                       # PreToolUse | PostToolUse | ...
    tool: str = ""
    taint: List[str] = field(default_factory=list)
    allowed_effects: List[str] = field(default_factory=list)

    @property
    def trust(self) -> float:
        return TRUST.get(self.origin, TRUST["unclassified"])

    @property
    def trust_class(self) -> str:
        return TRUST_CLASS.get(self.origin, UNCLASSIFIED)

    @property
    def agent_authored(self) -> bool:
        """True when the content is the agent's own planned action.

        Load-bearing: agent-authored text is a *plan*, not an inbound document,
        and must not be scanned as though an untrusted party wrote it.
        """
        return self.origin == "agent" and not self.taint

    @property
    def tainted(self) -> bool:
        return bool(self.taint)

    @property
    def destructive(self) -> bool:
        return self.tool in DESTRUCTIVE_TOOLS

    @property
    def egress(self) -> bool:
        return self.tool in EGRESS_TOOLS


def origin_for(tool: str, event: str) -> str:
    """Classify origin from the tool and hook event.

    The event matters: `WebFetch` *output* is inbound web content, while the
    same tool's *input* is a URL the agent chose.
    """
    if tool.startswith("mcp__"):
        return "mcp_tool" if event == "PostToolUse" else "agent"
    if event == "PostToolUse" and tool in INBOUND_TOOLS:
        return INBOUND_TOOLS[tool]
    if event == "PreToolUse" and tool in AGENT_AUTHORED_TOOLS:
        return "agent"
    if event == "PreToolUse":
        return "agent"
    return "unclassified"


def default_effects(origin: str) -> List[str]:
    """What content from this origin is allowed to do.

    Untrusted content may be read, quoted and cited. It may not supply the
    parameters of an action. The model may inspect it; it must not take
    authority from it.
    """
    if TRUST_CLASS.get(origin, UNCLASSIFIED) == UNTRUSTED:
        return ["summarize", "cite", "request_verification"]
    if TRUST_CLASS.get(origin, UNCLASSIFIED) == SEMI_TRUSTED:
        return ["summarize", "cite", "request_verification", "propose_action"]
    return ["summarize", "cite", "request_verification", "propose_action", "execute"]


def build(content: str, origin: Optional[str] = None, event: str = "",
          tool: str = "", taint: Optional[List[str]] = None) -> Event:
    resolved = origin or origin_for(tool, event)
    return Event(
        content=content,
        origin=resolved,
        event=event,
        tool=tool,
        taint=list(taint or []),
        allowed_effects=default_effects(resolved),
    )
