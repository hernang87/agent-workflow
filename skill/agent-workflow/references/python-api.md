# `workflow.py` Python API

These examples assume the repository's `workflow.py` is importable and
`Path` is imported. Keep durable state outside the source tree; the
orchestrator enforces that boundary.

## Common start and low-risk flow

```python
run = Orchestrator("task-id", Path("/tmp/agent-workflow/task.json"))
run.context.request = request
run.context.risk = "low"
run.activate()                 # preflight
run.route("low")
run.activate()                 # L1
run.route("pass")
run.activate()                 # L2
run.route("pass")
run.context.source_text = current_source_snapshot()
run.activate()                 # L3: write; source_text is required
run.route("pass")
run.activate()                 # L4: verify and commit node
run.record_commit(commit_hash, validation_output, head_hash=git_head)
run.route("pass")             # final audit -> merge-ready
report = run.final_report()
```

`current_source_snapshot()` is an application-level read of the working tree;
do not write that value into checkpoint data. The commit hash and `git_head`
must match, and `validation_output` must be non-empty.

## Medium-risk flow without plan approval

Run preflight, then `T1` through `T4`, activating and routing `"pass"` at
each node. At `approval-router`, route `"not-required"`, activate `T6` after
setting `run.context.source_text`, and route `"pass"`.

```python
run.activate(); run.route("medium")          # preflight
for _ in range(4):
    run.activate(); run.route("pass")        # T1..T4
run.activate(); run.route("not-required")    # approval-router -> T6
run.context.source_text = current_source_snapshot()
run.activate(); run.route("pass")            # T6 -> review-fanout
run.run_parallel_reviews()
outcome = run.join_reviews()
run.route(outcome)
```

Continue from the routed node. A clean join goes through `T9`, `T10`, `T12`,
and `T13`; activate each node and route `"pass"`. After `T12` passes, record
the verified commit before routing to `T13`:

```python
run.activate(); run.route("pass")            # T9
run.activate(); run.route("pass")            # T10
run.activate()                               # T12
run.record_commit(commit_hash, checks, head_hash=git_head)
run.route("pass")                            # T13 -> merge-ready
report = run.final_report()
```

## High-risk or ambiguous plan approval

At `approval-router`, route `"required"`, activate `astra-plan`, and route
`"pass"`. The next route opens `T5`; stop and hand the gate to a human.

```python
run.activate(); run.route("required")        # approval-router -> astra-plan
run.activate(); run.route("pass")            # astra-plan -> T5 gate
token = run.take_approval_token()             # deliver out-of-band to human
# stop; resume only after the human returns an explicit decision
run.decide(token, "approved")                 # or "revise", "rejected", "abort"
```

Never replace `decide()` with a guessed approval. `"revise"` routes back to
`T3`; `"rejected"`/`"abort"` terminate the relevant path.

## Review-fix cycle

After `join_reviews()` returns `"must-fix"`, route it to `T11`. Set
`source_text` to the post-fix source snapshot before activating `T11`; its
implementation revision invalidates old implementation evidence.

```python
run.route("must-fix")
run.context.source_text = fixed_source_snapshot()
run.activate(); run.route("pass")            # T11 -> review-fanout
run.run_parallel_reviews()
outcome = run.join_reviews()
run.route(outcome)
```

If the join returns `"no-progress"`, stop at `human-gate`. Conflicting
reviews route through `astra-adjudication`; follow its explicit outcome and
stop if it routes to a human gate.

## Missing acceptance path and waiver

Run `T9`, then if `T10` reports a blocked acceptance path, route
`"waiver-required"`. Stop at `human-waiver` and wait for the human token
decision:

```python
run.activate(); run.route("pass")            # T9
run.activate(); run.route("waiver-required") # blocked T10 -> waiver gate
token = run.take_approval_token()
# stop; only an explicit human decision may continue
run.decide(token, "approved")                # records the waiver -> T12
```

The waiver is durable evidence in `final_report()`; it is not a substitute for
acceptance validation unless the human explicitly approves it.

## Resume and completion checks

After a process restart, load the checkpoint with
`Orchestrator.resume(Path("/tmp/agent-workflow/task.json"))`. If a gate is
pending, call `reissue_gate()` and wait for the newly issued human decision.
Do not reuse an old token or bypass the gate.

Before saying `merge-ready`, confirm that the orchestrator itself has reached
that status and that `final_report()["commits"]` contains matching commit and
HEAD evidence. `final_audit()` is invoked by the terminal route; use its
failure as a blocker report, not as a reason to fabricate evidence.
