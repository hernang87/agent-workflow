# Agent Workflow

Risk-gated workflow orchestration for bounded software changes, bundled as a
Codex skill.

## Contents

- `skill/agent-workflow/scripts/workflow.py` — SQLite-backed `Orchestrator`, canonical `NODES` and `EDGES`, scope manifests, leases, risk routing, human gates, reviews, acceptance checks, commit evidence, and final reporting.
- `test_workflow.py` — unit tests for the graph and state invariants.
- `workflow.mmd` — Mermaid diagram generated from the canonical graph.
- `skill/agent-workflow/` — installable Codex skill and Python API examples.

## Installation

Copy the bundled skill into the Codex skills directory:

```bash
install_dir="${CODEX_HOME:-$HOME/.codex}/skills/agent-workflow"
mkdir -p "$install_dir"
cp -R skill/agent-workflow/. "$install_dir/"
```

Restart Codex after installation so it discovers the skill. Target repositories
provide scope data and executor callbacks; they do not need a `workflow.py`.

## Quick start

```python
import importlib.util
import os
import sys
from pathlib import Path

skill_dir = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")) / "skills" / "agent-workflow"
spec = importlib.util.spec_from_file_location("agent_workflow_harness", skill_dir / "scripts" / "workflow.py")
if spec is None or spec.loader is None:
    raise ImportError(f"cannot load workflow harness from {skill_dir}")
workflow = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = workflow
spec.loader.exec_module(workflow)
Orchestrator, ScopeManifest = workflow.Orchestrator, workflow.ScopeManifest

scope = ScopeManifest("source-revision", ("src/example.py",), ("unit-tests",))
run = Orchestrator("task-id", Path("/tmp/agent-workflow/workflow.db"), scope_manifest=scope,
                   executors={"implementation": implement, "validation": validate,
                              "acceptance": accept, "commit": verify_commit})
run.context.request = "Describe the bounded change"
run.context.risk = "low"
run.activate()       # preflight
run.route("low")
```

Continue through the routed nodes. Before a write node, set
`run.context.source_text` to the current source snapshot. Validation defaults
to affected targets; use `validation_mode="full"` explicitly for repository-wide
checks. Before reporting
`merge-ready`, run acceptance validation, verify committed `HEAD`, record it
with `record_commit(..., head_hash=...)`, and obtain `run.final_report()` after
the terminal route.

For complete medium-risk, high-risk, review-fix, waiver, and resume flows, see
[`skill/agent-workflow/references/python-api.md`](skill/agent-workflow/references/python-api.md).

## Human gates

High-risk or ambiguous plans pause at `T5`. Baseline failures, blockers,
review no-progress, conflicts requiring judgment, failed acceptance, and
missing acceptance paths can pause at `human-gate` or `human-waiver`. The
SQLite store uses WAL, foreign keys, busy timeouts, and a per-run lease. The
orchestrator issues a token; only an explicit human decision may resume,
reject, waive, or abort the run.

## Codex skill

The installation above makes the skill available from any target repository.
Target repositories provide scope data and executor callbacks; they do not need
a `workflow.py`.

Run the tests with:

```bash
python3 -m unittest -v test_workflow.py
```
