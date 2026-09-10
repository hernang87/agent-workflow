# Agent Workflow

Risk-gated workflow orchestration for bounded software changes, plus a Codex
skill that uses the orchestrator when it is present in a repository.

## Contents

- `workflow.py` — durable `Orchestrator`, canonical `NODES` and `EDGES`, risk routing, human gates, reviews, acceptance checks, commit evidence, and final reporting.
- `test_workflow.py` — unit tests for the graph and state invariants.
- `workflow.mmd` — Mermaid diagram generated from the canonical graph.
- `skill/agent-workflow/` — installable Codex skill and Python API examples.

## Quick start

```python
from pathlib import Path
from workflow import Orchestrator

run = Orchestrator("task-id", Path("/tmp/agent-workflow/task.json"))
run.context.request = "Describe the bounded change"
run.context.risk = "low"
run.activate()       # preflight
run.route("low")
```

Continue through the routed nodes. Before a write node, set
`run.context.source_text` to the current source snapshot. Before reporting
`merge-ready`, run acceptance validation, verify committed `HEAD`, record it
with `record_commit(..., head_hash=...)`, and obtain `run.final_report()` after
the terminal route.

For complete medium-risk, high-risk, review-fix, waiver, and resume flows, see
[`skill/agent-workflow/references/python-api.md`](skill/agent-workflow/references/python-api.md).

## Human gates

High-risk or ambiguous plans pause at `T5`. Baseline failures, blockers,
review no-progress, conflicts requiring judgment, failed acceptance, and
missing acceptance paths can pause at `human-gate` or `human-waiver`. The
orchestrator issues a token; only an explicit human decision may resume,
reject, waive, or abort the run.

## Codex skill

The skill is also installed globally at `~/.codex/skills/agent-workflow`, so it
can be considered in any repository that exposes a compatible `workflow.py`.
It does not add a CLI or duplicate the workflow implementation.

Validate the skill and run the tests with:

```bash
python3 /Users/hernan/ai-tools/skills/.system/skill-creator/scripts/quick_validate.py skill/agent-workflow
python3 -m unittest -v test_workflow.py
```
