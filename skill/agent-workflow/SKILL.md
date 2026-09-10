---
name: agent-workflow
description: Route coding tasks through the bundled workflow harness with Orchestrator, NODES, and EDGES.
---

# Agent Workflow

Use this skill when the user explicitly asks for this workflow or when the task
needs its risk-gated execution model. Load `scripts/workflow.py` from this
installed skill directory. The target repository does not need to contain a
`workflow.py`; it provides only an immutable `ScopeManifest` and callbacks for
implementation, validation, acceptance, and commit nodes.

The `Orchestrator` is the only graph and task-state controller. Durable state
is SQLite (WAL with foreign keys and busy timeouts); JSON checkpoints and JSONL
audits are not supported. Each run requires an immutable `ScopeManifest`, and
agents inspect,
implement, review, and validate; route outcomes, mutate task state, open gates,
persist checkpoints, and decide terminal status through the orchestrator.

Required operating rules:

- Run preflight first, establish a baseline, classify risk from evidence, and
  route only through the canonical graph in `EDGES`.
- Pass caller-owned executors for implementation, validation, acceptance, and
  commit nodes. A missing executor must block; repository commands stay outside
  this library. Validation defaults to affected targets and only a manifest
  with `validation_mode="full"` may request repository-wide checks.
- Keep the SQLite run lease while mutating state. A second owner must wait for
  lease expiry or an explicit `close()` before resuming.
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
