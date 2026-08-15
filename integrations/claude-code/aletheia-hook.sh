#!/usr/bin/env bash
# Aletheia hook adapter for Claude Code.
#
# Deliberately thin: it locates the package and hands stdin to the CLI. All
# Claude-specific behaviour lives in src/aletheia/hooks.py, and the decision to
# block (or not) lives in src/aletheia/policy.py. Nothing here decides anything.
#
# Default mode is shadow — every outcome exits 0. To enable enforcement, set
# ALETHEIA_MODE=enforce. Do that only once the audit log shows a false-block
# rate you can live with; the log is at ~/.claude/aletheia/audit.jsonl.
set -uo pipefail

ALETHEIA_HOME="${ALETHEIA_HOME:-$HOME/Projects/tools/aletheia}"
ALETHEIA_MODE="${ALETHEIA_MODE:-shadow}"
PY="${ALETHEIA_PYTHON:-python3}"

if [[ ! -d "$ALETHEIA_HOME/src/aletheia" ]]; then
  # A missing install must never break the agent. Fail open, say so once.
  echo "aletheia: not found at $ALETHEIA_HOME (set ALETHEIA_HOME); passing through" >&2
  exit 0
fi

PYTHONPATH="$ALETHEIA_HOME/src${PYTHONPATH:+:$PYTHONPATH}" \
  "$PY" -m aletheia.cli --mode "$ALETHEIA_MODE" --quiet
rc=$?

# In shadow mode the CLI already returns 0. This is a second, independent belt:
# if anything above misbehaves — a crashed interpreter, a bad flag — the hook
# still must not block the agent while we are only observing.
if [[ "$ALETHEIA_MODE" != "enforce" ]]; then
  exit 0
fi
exit $rc
