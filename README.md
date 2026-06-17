# Aletheia

*Ἀλήθεια* — truth as the removal of concealment.

A prompt-injection detection agent for Claude. She tracks the **provenance** of
content and flags the moment an untrusted source tries to supply a parameter
that will govern an action — a version number, a file path, a command — and have
it acted on as if the user had said it.

Born 2026-06-17 from a live injection incident. The why is in
[`CLAUDE.md`](./CLAUDE.md); this file is the how.

## The idea

Injection works when content from a low-trust source arrives structured to look
like instruction, carries urgency, claims authority, and names specific values
meant to be acted on — and the agent treats those values as if they came from
the principal. The fix is not blanket skepticism (that makes an agent useless).
The fix is provenance: **every parameter that governs an action must have a
declared source, and untrusted sources cannot supply governing parameters
without the human knowing.**

### Source trust

| source | trust | |
|--------|-------|--|
| `user` | 1.0 | the principal — what they say governs |
| `file` | 0.9 | the codebase, committed, version-controlled |
| `mcp_tool` | 0.5 | depends on the tool; can be compromised |
| `web_search` | 0.2 | can be crafted — was crafted |
| `web_fetch` | 0.2 | same |
| `clipboard` | 0.1 | unknown origin; maximum suspicion |
| `unknown` | 0.3 | default |

### Scoring

Five pattern families carry weights: governing parameters (0.30), urgency
(0.25), prescriptive commands (0.35), authority claims (0.20), structural
mimicry (0.30). Governing-params **and** prescriptive together add a +0.25 combo
penalty (the canonical injection shape). Urgency multiplies the content risk by
1.3. The final score scales content risk by source distrust:

```
score = min(1, content_risk × (0.4 + 0.6 × (1 − source_trust)))
```

`< 0.3` proceed · `0.3–0.6` verify · `> 0.6` stop.

## Architecture

```
assess.ts  / assess.py   pure pattern detection — no SDK, no API, no network
index.ts   / main.py     SDK agent wrapper + hook callbacks + CLI
```

The split is deliberate: the part that **judges** has zero dependencies, so it
can run inside a hook on the standard library alone. The SDK is only needed for
the optional `--enrich` path, which asks an LLM to write the human-facing
reasoning for a flagged item.

## Run it

### Python (no build, no dependencies for the core)

```sh
cd python
python3 main.py --source web_search < examples/incident-websearch.txt   # → exit 2 (stop)
python3 main.py --source web_search < examples/benign-websearch.txt      # → exit 0 (proceed)
```

### TypeScript

```sh
cd typescript
npm install
npm run typecheck          # type-clean
npm run build              # bundles to dist/index.js via esbuild
echo "content" | node dist/index.js --source web_search
```

## Wire into Claude Code

Copy the hook blocks from [`settings-template.json`](./settings-template.json)
into your `settings.json`. The CLI reads a hook JSON payload (or raw text with
`--source`) on stdin, prints the assessment as JSON, writes the reasoning to
stderr when it is not "proceed", and exits `0`/`1`/`2`. On a `PreToolUse` hook,
exit `2` blocks the tool and surfaces the reason to Claude.

## What she does not do

She is a layer, not a cure. She assesses content arriving from tools — web
results, MCP output — and the inputs to `Bash`/`Edit`/`Write`. She does **not**
audit the `user` channel (trust 1.0 by design), and she cannot score the agent's
own momentum. The two channels that are hardest to guard are the ones labelled
*self*: an instruction pasted as if from the principal, and the agent's own urge
to finish. Those limits are real and are kept in the record on purpose.
