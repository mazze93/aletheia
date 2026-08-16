"""The hook adapter, exercised as the system actually runs it.

Every other test in this suite calls Python functions. This one runs the shell
script that Claude Code invokes, through a real payload on stdin, and reads the
audit log it writes. It exists because the shadow-mode check proves *detection*,
and detection is not the property that matters once `ALETHEIA_MODE=enforce` is
set — the property that matters then is that a detected payload actually stops
the tool call, and that the stop is recorded.

The payload is the issue-3 evasion in its natural habitat: every keyword
decorated with a non-ASCII letter at its boundary. Under the pre-fix patterns
exactly one family matched (`high-severity`) and the payload sailed through. It
is used here rather than a plain injection so this test fails if the boundary
policy is ever unwound, no matter what the unit tests say.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
HOOK = ROOT / "integrations" / "claude-code" / "aletheia-hook.sh"
PAYLOAD = ROOT / "tests" / "fixtures" / "unicode-boundary-adversarial-payload.json"

BLOCK, WARN, OK = 2, 1, 0


def run_hook(mode: str) -> tuple[int, str, list[dict]]:
    """Invoke the adapter exactly as a hook would. Returns (exit, stderr, audit)."""
    with tempfile.TemporaryDirectory() as tmp:
        log = pathlib.Path(tmp) / "audit.jsonl"
        env = {
            **os.environ,
            "ALETHEIA_HOME": str(ROOT),
            "ALETHEIA_MODE": mode,
            "ALETHEIA_AUDIT_LOG": str(log),
        }
        proc = subprocess.run(
            ["bash", str(HOOK)],
            input=PAYLOAD.read_text(encoding="utf-8"),
            capture_output=True,
            text=True,
            env=env,
        )
        events = []
        if log.is_file():
            events = [
                json.loads(line)
                for line in log.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        return proc.returncode, proc.stderr, events


class EnforceModeBlocks(unittest.TestCase):
    """The security property, at the layer where it is actually enforced."""

    def test_adversarial_payload_blocks_the_tool_call(self):
        code, stderr, events = run_hook("enforce")
        self.assertEqual(code, BLOCK, f"expected exit 2, got {code}\n{stderr}")
        self.assertIn("STOP", stderr)

    def test_the_block_is_recorded_with_factors_and_action(self):
        """A block nobody can explain afterwards is not much better than none."""
        _, _, events = run_hook("enforce")
        self.assertEqual(len(events), 1, "expected exactly one audit event")
        e = events[0]
        self.assertEqual(e["action"], "stop")
        self.assertTrue(e["would_block"])
        self.assertTrue(e["enforced"])
        self.assertEqual(e["mode"], "enforce")
        self.assertEqual(e["origin"], "web_search")
        self.assertEqual(e["hook_event"], "PostToolUse")
        self.assertGreaterEqual(e["score"], 0.6)

        categories = {f["category"] for f in e["features"]}
        self.assertIn("urgency", categories)
        self.assertIn("governing_parameter", categories)
        self.assertGreaterEqual(
            len(categories), 3,
            "the boundary policy should recover several families here; only "
            f"{sorted(categories)} fired — has it been unwound?",
        )

    def test_audit_stores_a_hash_not_the_payload(self):
        """MAX posture, checked at the layer that writes to disk."""
        _, _, events = run_hook("enforce")
        e = events[0]
        self.assertNotIn("content", e)
        self.assertTrue(e["content_hash"].startswith("blake2s:"))


class ShadowModeDetectsWithoutBlocking(unittest.TestCase):
    def test_same_payload_exits_zero_but_records_the_verdict(self):
        code, stderr, events = run_hook("shadow")
        self.assertEqual(code, OK, f"shadow mode must never block; got {code}")
        self.assertIn("shadow mode", stderr)
        self.assertEqual(events[0]["action"], "stop")
        self.assertTrue(events[0]["would_block"])
        self.assertFalse(events[0]["enforced"])


class AdapterFailsOpen(unittest.TestCase):
    """A missing install must not break the agent."""

    def test_missing_home_passes_through_without_blocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {**os.environ, "ALETHEIA_HOME": tmp, "ALETHEIA_MODE": "enforce"}
            proc = subprocess.run(
                ["bash", str(HOOK)],
                input=PAYLOAD.read_text(encoding="utf-8"),
                capture_output=True, text=True, env=env,
            )
        self.assertEqual(proc.returncode, OK)
        self.assertIn("not found", proc.stderr)


if __name__ == "__main__":
    unittest.main()
