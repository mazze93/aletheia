"""Aletheia — Ἀλήθεια, truth as the removal of concealment.

A prompt-injection detection agent for Claude. She tracks the provenance of
content and flags the moment an untrusted source tries to supply a parameter
that will govern an action.

The package is layered so that judging and enforcing are separable:

    assess      classify content, explain the score. Decides nothing.
    provenance  where content came from; trust and carried taint.
    policy      the only module that decides whether anything blocks.
    audit       append-only JSONL evidence; hashes, not payloads.
    hooks       Claude Code adapter: payload shape and exit semantics.
    cli         the entry point a hook invokes.
"""

__version__ = "0.2.0"

from .assess import Assessment, assess  # noqa: F401
from .policy import Decision, decide, ENFORCE, SHADOW  # noqa: F401
from .provenance import Event, build  # noqa: F401
