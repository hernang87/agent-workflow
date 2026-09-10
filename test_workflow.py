from pathlib import Path
import os
import tempfile
import unittest

from workflow import Context, EDGES, NODES, Orchestrator, Result, ReviewAgent, StaleResultError, mermaid


class WorkflowTests(unittest.TestCase):
    def make(self, directory: str, risk: str = "medium", **context) -> Orchestrator:
        orchestrator = Orchestrator("task-1", Path(directory) / "checkpoint.json")
        orchestrator.context = Context("task-1", risk=risk, **context)
        orchestrator.context.source_text = "initial source snapshot"
        orchestrator.activate()
        orchestrator.route(risk)
        return orchestrator

    def run_node(self, orchestrator: Orchestrator, outcome: str = "pass") -> None:
        orchestrator.activate()
        if orchestrator.state.current_node in {"L4", "T12"}:
            orchestrator.record_commit("abcdef1234567", ["HEAD verification: pass"], "abcdef1234567")
        orchestrator.route(outcome)

    def reach_reviews(self, orchestrator: Orchestrator) -> None:
        for _ in range(4):
            self.run_node(orchestrator)
        orchestrator.activate()
        orchestrator.route("not-required")  # approval-router -> T6
        self.run_node(orchestrator)  # T6 -> review-fanout

    def test_topology_and_model_policy(self):
        self.assertEqual(NODES["L3"].model, "gpt-5.6-terra")
        self.assertEqual(NODES["L3"].reasoning_effort, "medium")
        self.assertEqual(NODES["T6"].reasoning_effort, "high")
        self.assertEqual(NODES["T7"].model, "gpt-5.6-sol")
        self.assertEqual(NODES["astra-adjudication"].model, "gpt-6-astra")
        self.assertEqual(NODES["astra-adjudication"].reasoning_effort, "high")
        self.assertTrue(any(e.source == "T9" and e.target == "T10" for e in EDGES))
        self.assertTrue(any(e.source == "T11" and e.target == "review-fanout" for e in EDGES))

    def test_low_risk_uses_only_low_risk_path(self):
        with tempfile.TemporaryDirectory() as directory:
            orchestrator = self.make(directory, "low")
            self.assertEqual(set(orchestrator.state.tasks), {"L1", "L2", "L3", "L4"})
            for _ in range(4):
                self.run_node(orchestrator)
            self.assertEqual(orchestrator.state.status, "merge-ready")
            self.assertNotIn("T7", orchestrator.attempts)

    def test_medium_plan_skips_human_approval_and_cancels_T5(self):
        with tempfile.TemporaryDirectory() as directory:
            orchestrator = self.make(directory)
            self.assertEqual(orchestrator.state.tasks["T5"].status, "cancelled")
            for _ in range(4):
                self.run_node(orchestrator)
            self.assertEqual(orchestrator.state.current_node, "approval-router")
            orchestrator.activate()
            orchestrator.route("not-required")
            self.assertEqual(orchestrator.state.current_node, "T6")

    def test_high_risk_requires_astra_and_fingerprint_bound_human_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            orchestrator = self.make(directory, "high")
            for _ in range(4):
                self.run_node(orchestrator)
            orchestrator.activate()
            orchestrator.route("required")
            self.assertEqual(orchestrator.state.current_node, "astra-plan")
            self.run_node(orchestrator)
            self.assertEqual(orchestrator.state.status, "awaiting-human")
            token = orchestrator.take_approval_token()
            with self.assertRaises(PermissionError):
                orchestrator.decide("wrong-token", "approved")
            orchestrator.decide(token, "approved")
            self.assertEqual(orchestrator.state.current_node, "T6")
            self.assertEqual(orchestrator.state.tasks["T5"].status, "done")

    def test_task_dependencies_and_evidence_are_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            orchestrator = Orchestrator("task-1", Path(directory) / "checkpoint.json")
            orchestrator.create_task("a", "first", "first", "owner")
            orchestrator.create_task("b", "second", "second", "owner", ["a"])
            with self.assertRaises(ValueError): orchestrator.update_task("b", "active")
            with self.assertRaises(ValueError): orchestrator.update_task("a", "done")
            orchestrator.update_task("a", "done", ({"test": "passed"},))
            orchestrator.update_task("b", "active")
            with self.assertRaises(ValueError): orchestrator.update_task("b", "blocked", reason="blocked")

    def test_baseline_failure_is_not_silently_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            orchestrator = self.make(directory, "medium", baseline_passed=False)
            result = orchestrator.activate()
            self.assertEqual(result.status, "fail")
            self.assertEqual(orchestrator.state.tasks["T1"].status, "failed")
            orchestrator.route("baseline-fail")
            self.assertEqual(orchestrator.state.status, "awaiting-human")

    def test_checkpoint_is_private_atomic_audited_and_resumable(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "run" / "checkpoint.json"
            orchestrator = Orchestrator("task-1", store)
            orchestrator.context.request = "do work with api_key=do-not-store"
            orchestrator.context.source_text = "source should not be stored"
            orchestrator.state.evidence.append({"api_key": "do-not-store", "message": "token=also-do-not-store"})
            orchestrator.checkpoint("created")
            self.assertEqual(os.stat(store).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(store.parent).st_mode & 0o777, 0o700)
            self.assertTrue(store.with_name("events.jsonl").exists())
            resumed = Orchestrator.resume(store)
            self.assertEqual(resumed.state.task_id, "task-1")
            self.assertEqual(resumed.state.graph_fingerprint, orchestrator.state.graph_fingerprint)
            persisted = store.read_text()
            self.assertNotIn("do-not-store", persisted)
            self.assertNotIn("also-do-not-store", persisted)
            self.assertNotIn("source should not be stored", persisted)
            with self.assertRaises(ValueError):
                Orchestrator("task-1", Path(__file__).parent / "checkpoint.json")

    def test_revision_change_invalidates_only_implementation_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            orchestrator = Orchestrator("task-1", Path(directory) / "checkpoint.json")
            orchestrator.state.evidence = [{"scope": "run"}, {"scope": "implementation"}]
            orchestrator.context.review_results.append({"node_id": "T7", "implementation_revision": 0})
            orchestrator.bump_implementation_revision("new diff")
            self.assertEqual(orchestrator.state.implementation_revision, 1)
            self.assertEqual(orchestrator.state.evidence, [{"scope": "run"}])
            self.assertFalse(orchestrator.context.review_results)

    def test_review_join_detects_no_progress(self):
        with tempfile.TemporaryDirectory() as directory:
            orchestrator = self.make(directory)
            self.reach_reviews(orchestrator)
            for node_id in ("T7", "T8"):
                orchestrator.agents[node_id] = ReviewAgent(node_id, lambda _: ("must-fix", ["A", "B"]))
            orchestrator.run_parallel_reviews()
            self.assertEqual(orchestrator.join_reviews(), "must-fix")
            orchestrator.route("must-fix")
            orchestrator.context.source_text = "fixed source snapshot"
            self.run_node(orchestrator)
            for node_id in ("T7", "T8"):
                orchestrator.agents[node_id] = ReviewAgent(node_id, lambda _: ("must-fix", ["A", "B"]))
            orchestrator.run_parallel_reviews()
            self.assertEqual(orchestrator.join_reviews(), "no-progress")

    def test_stale_review_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            orchestrator = Orchestrator("task-1", Path(directory) / "checkpoint.json")
            orchestrator.state.implementation_revision = 2
            stale = Result("T7", 1, "task-1", 1, 1, "pass")
            with self.assertRaises(StaleResultError): orchestrator._normalize(stale)

    def test_medium_clean_path_reaches_merge_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            orchestrator = self.make(directory)
            self.reach_reviews(orchestrator)
            orchestrator.run_parallel_reviews()
            outcome = orchestrator.join_reviews()
            self.assertEqual(outcome, "clean")
            orchestrator.route(outcome)
            self.run_node(orchestrator)  # T9
            self.run_node(orchestrator)  # T10
            self.run_node(orchestrator)  # T12
            self.run_node(orchestrator)  # T13 -> merge-ready
            self.assertEqual(orchestrator.state.status, "merge-ready")
            self.assertEqual(orchestrator.state.tasks["T11"].status, "cancelled")

    def test_missing_acceptance_path_requires_explicit_waiver(self):
        with tempfile.TemporaryDirectory() as directory:
            orchestrator = self.make(directory, acceptance_path=False)
            self.reach_reviews(orchestrator)
            orchestrator.run_parallel_reviews()
            orchestrator.route(orchestrator.join_reviews())
            self.run_node(orchestrator)  # T9
            result = orchestrator.activate()  # T10
            self.assertEqual(result.status, "blocked")
            orchestrator.route("waiver-required")
            token = orchestrator.take_approval_token()
            orchestrator.decide(token, "approved")
            self.assertTrue(orchestrator.context.waiver)
            self.assertEqual(orchestrator.state.tasks["T10"].status, "done")
            self.assertEqual(orchestrator.state.current_node, "T12")

    def test_low_risk_can_escalate_without_deleting_old_tasks(self):
        with tempfile.TemporaryDirectory() as directory:
            orchestrator = self.make(directory, "low")
            self.run_node(orchestrator)  # L1
            orchestrator.escalate_risk("high", "authentication boundary discovered")
            self.assertEqual(orchestrator.state.current_node, "T1")
            self.assertIn("L1", orchestrator.state.tasks)
            self.assertIn("T13", orchestrator.state.tasks)
            self.assertEqual(orchestrator.state.tasks["L2"].status, "cancelled")
            self.assertEqual(orchestrator.state.tasks["T6"].dependencies, ["T5"])

    def test_final_report_records_commits_waivers_and_accepted_risks(self):
        with tempfile.TemporaryDirectory() as directory:
            orchestrator = Orchestrator("task-1", Path(directory) / "checkpoint.json")
            orchestrator.state.risk = "high"
            with self.assertRaises(PermissionError):
                orchestrator.accept_risk("temporary gap", "limited exposure", "orchestrator", "issue-123")
            orchestrator.accept_risk("temporary gap", "limited exposure", "human", "issue-123")
            orchestrator.state.current_node = "T12"
            orchestrator.state.node_states["T12"] = "done"
            orchestrator.record_commit("abcdef1234567", ["HEAD verification: pass"], "abcdef1234567")
            report = orchestrator.final_report()
            self.assertEqual(report["accepted_risks"][0]["approver"], "human")
            self.assertEqual(report["commits"][0]["hash"], "abcdef1234567")

    def test_mermaid_is_generated_from_canonical_graph(self):
        diagram = mermaid()
        self.assertIn("review_join -->|conflict| astra_adjudication", diagram)
        self.assertIn("review_fanout -->|ordinary| T7", diagram)
        self.assertIn("review_fanout -->|adversarial| T8", diagram)
        self.assertEqual(Path(__file__).with_name("workflow.mmd").read_text(), diagram)
        self.assertIn("class astra_plan,astra_adjudication escalation", diagram)


if __name__ == "__main__":
    unittest.main()
