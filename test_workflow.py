from pathlib import Path
import importlib.util
import os
import sqlite3
import sys
import tempfile
import unittest

SKILL_HARNESS = Path(__file__).parent / "skill" / "agent-workflow" / "scripts" / "workflow.py"
SPEC = importlib.util.spec_from_file_location("agent_workflow_harness", SKILL_HARNESS)
if SPEC is None or SPEC.loader is None:
    raise ImportError(f"cannot load workflow harness from {SKILL_HARNESS}")
workflow = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = workflow
SPEC.loader.exec_module(workflow)

Budget, Context, EDGES, NODES, Orchestrator, Result, ReviewAgent = (
    workflow.Budget, workflow.Context, workflow.EDGES, workflow.NODES,
    workflow.Orchestrator, workflow.Result, workflow.ReviewAgent,
)
ScopeManifest, StaleResultError, LeaseError, mermaid = (
    workflow.ScopeManifest, workflow.StaleResultError, workflow.LeaseError,
    workflow.mermaid,
)


def passing(_context, _state, _attempt):
    return {"status": "pass", "evidence": ({"check": "passed"},)}


def accepting(context, state, attempt):
    return passing(context, state, attempt) if context.acceptance_path else {"status": "blocked", "evidence": ({"acceptance_path": "unavailable"},)}


def scope(revision="r1"):
    return ScopeManifest(revision, ("src/example.py",), ("unit-tests",))


class WorkflowTests(unittest.TestCase):
    def make(self, directory, risk="medium", **context):
        run = Orchestrator(
            "task-1", Path(directory) / "workflow.db", scope_manifest=scope(),
            executors={"implementation": passing, "validation": passing,
                       "acceptance": accepting, "commit": passing},
        )
        run.context.risk = risk
        for key, value in context.items():
            setattr(run.context, key, value)
        run.activate()
        run.route(risk)
        return run

    def run_node(self, run):
        result = run.activate()
        if run.state.current_node in {"L4", "T12"} and result.status == "pass":
            run.record_commit("abcdef1234567", ("HEAD verification: pass",), "abcdef1234567")
        run.route(result.status)
        return result

    def reach_reviews(self, run):
        for _ in range(4):
            self.run_node(run)
        if run.state.current_node == "approval-router":
            run.route("not-required")
        run.context.source_text = "implemented source"
        self.run_node(run)

    def test_graph_and_mermaid_keep_canonical_review_routes(self):
        self.assertEqual(NODES["L3"].model, "gpt-5.6-terra")
        self.assertTrue(any(e.source == "T9" and e.target == "T10" for e in EDGES))
        self.assertIn("review_join -->|conflict| astra_adjudication", mermaid())

    def test_low_risk_path_uses_executors_and_reaches_merge_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.make(directory, "low")
            self.run_node(run)
            self.run_node(run)
            run.context.source_text = "new source"
            self.run_node(run)
            self.run_node(run)
            self.assertEqual(run.state.status, "merge-ready")

    def test_missing_executor_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Orchestrator("task-1", Path(directory) / "workflow.db",
                               scope_manifest=scope())
            run.context.risk = "low"
            run.activate()
            run.route("low")
            result = run.activate()
            self.assertEqual(result.status, "blocked")
            self.assertEqual(run.state.tasks["L1"].status, "blocked")
            self.assertEqual(run.route("blocked"), "human-gate")

    def test_harness_runs_from_repo_without_workflow_module(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "unrelated-repo"
            repo.mkdir()
            self.assertFalse((repo / "workflow.py").exists())
            previous_cwd = Path.cwd()
            try:
                os.chdir(repo)
                run = self.make(directory, "low")
                self.run_node(run)
                self.run_node(run)
                run.context.source_text = "new source"
                self.run_node(run)
                self.run_node(run)
                self.assertEqual(run.state.status, "merge-ready")
            finally:
                os.chdir(previous_cwd)

    def test_sqlite_resume_and_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workflow.db"
            run = Orchestrator("task-1", path, scope_manifest=scope())
            run.activate()
            with self.assertRaises(LeaseError):
                Orchestrator.resume(path)
            run.close()
            resumed = Orchestrator.resume(path, scope_manifest=scope())
            self.assertEqual(resumed.state.current_node, "preflight")
            conn = sqlite3.connect(path)
            self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0], "wal")
            conn.close()
            self.assertFalse(list(path.parent.glob("*.jsonl")))

    def test_scope_hash_invalidates_evidence_and_gate_decisions(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.make(directory, "high")
            for _ in range(4):
                self.run_node(run)
            run.route("required")
            self.run_node(run)
            token = run.take_approval_token()
            run.state.scope_hash = "stale"
            with self.assertRaises(StaleResultError):
                run.decide(token, "approved")

    def test_invalid_decision_preserves_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.make(directory, "high")
            for _ in range(4):
                self.run_node(run)
            run.route("required")
            self.run_node(run)
            token = run.take_approval_token()
            gate = dict(run.state.pending_gate)
            with self.assertRaises(ValueError):
                run.decide(token, "not-a-decision")
            self.assertEqual(run.state.pending_gate, gate)
            run.decide(token, "approved")

    def test_transition_budget_is_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Orchestrator("task-1", Path(directory) / "workflow.db",
                               Budget(max_transitions=2), scope_manifest=scope())
            run.activate()
            with self.assertRaises(RuntimeError):
                run.route("medium")
            self.assertLessEqual(len(run.state.transitions), 2)

    def test_evidence_is_redacted_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            huge = {"output": "x" * 70000}
            run = Orchestrator("task-1", Path(directory) / "workflow.db",
                               scope_manifest=scope(),
                               executors={"validation": lambda *_: {"status": "pass", "evidence": (huge,)}})
            run.context.risk = "low"
            run.activate()
            run.route("low")
            with self.assertRaises(ValueError):
                run.activate()
            run.close()
            run = Orchestrator("task-2", Path(directory) / "bounded.db",
                               scope_manifest=scope(),
                               executors={"validation": lambda *_: {"status": "pass", "evidence": ({"digest": "abc", "reference": "artifact://1", "secret": "token=x"},)}})
            run.context.risk = "low"
            run.activate(); run.route("low")
            self.assertEqual(run.activate().status, "pass")
            self.assertEqual(run.state.evidence[-1]["payload"]["secret"], "[REDACTED]")

    def test_transaction_rolls_back(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Orchestrator("task-1", Path(directory) / "workflow.db", scope_manifest=scope())
            run.activate()
            before = len(run.state.transitions)
            run._verify_lease = lambda _conn: (_ for _ in ()).throw(RuntimeError("write failed"))
            with self.assertRaises(RuntimeError):
                run.checkpoint("should-rollback")
            self.assertEqual(len(run.state.transitions), before)

    def test_acceptance_waiver_and_commit_are_scope_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.make(directory, acceptance_path=False)
            self.reach_reviews(run)
            run.run_parallel_reviews()
            run.route(run.join_reviews())
            self.run_node(run)
            result = run.activate()
            self.assertEqual(result.status, "blocked")
            run.route("waiver-required")
            token = run.take_approval_token()
            run.decide(token, "approved")
            self.run_node(run)
            self.run_node(run)
            self.assertEqual(run.state.status, "merge-ready")
            self.assertEqual(run.state.commits[-1]["scope_hash"], run.state.scope_hash)

    def test_large_synthetic_task_store(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Orchestrator("large", Path(directory) / "workflow.db",
                               Budget(max_transitions=2000), scope_manifest=scope())
            for index in range(1000):
                run.create_task(f"task-{index}", "synthetic", "synthetic", "owner")
            self.assertEqual(len(run.state.tasks), 1000)
            run.close()


if __name__ == "__main__":
    unittest.main()
