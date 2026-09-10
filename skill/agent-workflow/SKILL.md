---
name: agent-workflow
description: Route coding tasks through a repository's existing workflow.py orchestrator when it exposes Orchestrator, NODES, and EDGES; do not apply this skill when that workflow is absent.
---

# Agent Workflow

Use this skill when the repository contains `workflow.py` with `Orchestrator`,
`NODES`, and `EDGES`, or when the user explicitly asks for this workflow.
Import and use that repository's implementation directly. Do not invent a
parallel graph, CLI, or replacement workflow when the file is absent.

The `Orchestrator` is the only graph and task-state controller. Agents inspect,
implement, review, and validate; route outcomes, mutate task state, open gates,
persist checkpoints, and decide terminal status through the orchestrator.

Required operating rules:

- Run preflight first, establish a baseline, classify risk from evidence, and
  route only through the canonical graph in `EDGES`.
- Before every write node (`L3`, `T6`, or `T11`), set `orchestrator.context.source_text`
  to the current source snapshot. This is required for the implementation
  revision and intended diff hash. Refresh it to the new source before a later
  write revision. The orchestrator deliberately excludes it from checkpoints;
  never persist it separately as workflow state.
- For ordinary and adversarial review, call
  `run_parallel_reviews()`, then `join_reviews()`, and route the returned
  outcome. Do not run only one review or accept stale revision evidence.
- Stop at `T5`, `human-gate`, or `human-waiver`. Surface the reason and pending
  decision, then wait for an explicit human decision; do not approve, reject,
  resume, waive, or abort on the human's behalf.
- Treat review findings as evidence. Repair only routed must-fix findings,
  refresh `source_text`, and repeat the parallel review cycle. Stop for
  `no-progress`, disagreement requiring adjudication, blockers, failed
  acceptance, or a required waiver.
- Run acceptance validation (`T9` and the real scenario at `T10` for the
  non-low-risk path). After the commit-verification node passes, verify the
  actual committed `HEAD` and call
  `record_commit(commit_hash, command_results, head_hash=...)` with matching
  hashes. Do not report `merge-ready` without this evidence.
- Route through the final audit (`L4`/`T13`) and call `final_report()` only
  after the orchestrator reaches `merge-ready`. Report status, risk, evidence,
  revisions, reviews, commits, waivers/accepted risks, and unresolved
  blockers. If a gate or error remains, report it plainly instead.

Read [references/python-api.md](references/python-api.md) for the current API
ordering and compact flow examples.
