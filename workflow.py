"""Risk-gated, durable execution graph for bounded software changes.

Agents return structured evidence. Only :class:`Orchestrator` mutates graph or
task state, chooses routes, opens human gates, and persists the run.
"""

from __future__ import annotations

from ast import literal_eval
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
from typing import Any, Callable, Iterable, Literal
import uuid


RESULT_STATUSES = {"pass", "fail", "blocked"}
RUN_STATUSES = {"running", "awaiting-human", "merge-ready", "aborted"}
TASK_STATUSES = {"pending", "active", "blocked", "failed", "done", "cancelled"}
RISK_LEVELS = {"low", "medium", "high"}
RISK_ORDER = {"low": 0, "medium": 1, "high": 2}
SENSITIVE_KEY_PARTS = {"token", "secret", "password", "credential", "api_key", "environment"}
SECRET_VALUE = re.compile(r"(?i)(\b(?:api[_-]?key|token|secret|password|credential|authorization)\b\s*[:=]\s*)([^\s,;]+)")
BEARER_VALUE = re.compile(r"(?i)(\bbearer\s+)([^\s,;]+)")
HUMAN_NODES = {"T5", "human-gate", "human-waiver"}
WRITE_NODES = {"L3", "T6", "T11"}
REVIEW_NODES = {"T7", "T8"}
IMPLEMENTATION_NODES = WRITE_NODES
VALIDATION_NODES = {"L1", "T1", "T9", "T13"}
ACCEPTANCE_NODES = {"T10"}
COMMIT_NODES = {"L4", "T12"}
HOOK_NODES = IMPLEMENTATION_NODES | VALIDATION_NODES | ACCEPTANCE_NODES | COMMIT_NODES
MAX_EVIDENCE_BYTES = 64 * 1024


class StaleResultError(RuntimeError):
    """Evidence was produced against an obsolete graph or implementation."""


class LeaseError(RuntimeError):
    """Another process owns the run lease."""


@dataclass(frozen=True)
class ScopeManifest:
    revision: str
    changed_files: tuple[str, ...]
    affected_targets: tuple[str, ...]
    validation_mode: Literal["changed", "full"] = "changed"

    def __post_init__(self) -> None:
        object.__setattr__(self, "changed_files", tuple(self.changed_files))
        object.__setattr__(self, "affected_targets", tuple(self.affected_targets))
        if not self.revision or self.validation_mode not in {"changed", "full"}:
            raise ValueError("scope manifest requires a revision and valid validation mode")
        if any(not item or item.startswith("/") or ".." in Path(item).parts
               for item in (*self.changed_files, *self.affected_targets)):
            raise ValueError("scope paths must be non-empty relative paths")

    @property
    def hash(self) -> str:
        value = "\n".join((self.revision, self.validation_mode, *self.changed_files,
                            "--targets--", *self.affected_targets))
        return hashlib.sha256(value.encode()).hexdigest()


@dataclass(frozen=True)
class Node:
    id: str
    type: str
    owner: str
    model: str
    reasoning_effort: str
    permission: str
    action: str
    required_inputs: tuple[str, ...] = ()
    expected_outputs: tuple[str, ...] = ()
    acceptance_evidence: tuple[str, ...] = ()
    input_revision: str = "context"
    output_revision: str = "context"
    idempotency: str = "replay-safe"
    preconditions: tuple[str, ...] = ()
    success_route: tuple[str, ...] = ()
    failure_route: tuple[str, ...] = ()


@dataclass(frozen=True)
class Edge:
    source: str
    outcome: str
    target: str


@dataclass
class Task:
    id: str
    description: str
    goal: str
    owner: str
    status: str = "pending"
    dependencies: list[str] = field(default_factory=list)
    acceptance_evidence: list[dict[str, Any]] = field(default_factory=list)
    affected_files_or_subsystem: list[str] = field(default_factory=list)
    reason: str = ""
    next_action: str = ""

    def __post_init__(self) -> None:
        if self.status not in TASK_STATUSES:
            raise ValueError(f"unknown task status: {self.status}")


@dataclass(frozen=True)
class Budget:
    max_node_attempts: int = 3
    max_transitions: int = 200
    max_parallel: int = 2
    # None follows the chosen policy: continue only while progress is measurable.
    max_review_cycles: int | None = None


@dataclass
class State:
    task_id: str
    context_revision: int = 0
    task_list_revision: int = 0
    implementation_revision: int = 0
    intended_diff_hash: str = ""
    current_node: str = "preflight"
    status: str = "running"
    risk: str = "unknown"
    approval_required: bool = False
    graph_fingerprint: str = ""
    scope_hash: str = ""
    tasks: dict[str, Task] = field(default_factory=dict)
    node_states: dict[str, str] = field(default_factory=dict)
    node_outputs: dict[str, dict[str, Any]] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    transitions: list[dict[str, Any]] = field(default_factory=list)
    review_cycles: list[dict[str, Any]] = field(default_factory=list)
    previous_must_fixes: list[str] = field(default_factory=list)
    accepted_risks: list[dict[str, str]] = field(default_factory=list)
    waivers: list[dict[str, str]] = field(default_factory=list)
    commits: list[dict[str, Any]] = field(default_factory=list)
    pending_gate: dict[str, Any] | None = None


@dataclass(frozen=True)
class Result:
    node_id: str
    attempt: int
    task_id: str
    input_revision: int
    implementation_revision: int
    status: str
    evidence: tuple[dict[str, Any], ...] = ()
    findings: tuple[str, ...] = ()
    uncertainties: tuple[str, ...] = ()
    recommended_next_action: str = ""
    scope_hash: str = ""

    def __post_init__(self) -> None:
        if self.status not in RESULT_STATUSES:
            raise ValueError(f"unknown result status: {self.status}")


@dataclass
class Context:
    """Sanitized run context. It must never contain credentials or tokens."""

    task_id: str
    request: str = ""
    risk: str = "unknown"
    ambiguity: bool = False
    approval_required: bool = False
    baseline_passed: bool = True
    acceptance_path: bool = True
    waiver: bool = False
    findings: list[str] = field(default_factory=list)
    changed_source: bool = False
    review_results: list[dict[str, Any]] = field(default_factory=list)
    source_text: str = ""
    scope_manifest: ScopeManifest | None = None


def n(id: str, type: str, owner: str, model: str, effort: str, permission: str,
      action: str, inputs: Iterable[str] = (), outputs: Iterable[str] = (),
      input_revision: str = "context", output_revision: str = "context",
      idempotency: str = "replay-safe") -> Node:
    return Node(id, type, owner, model, effort, permission, action, tuple(inputs),
                tuple(outputs), (), input_revision, output_revision, idempotency)


NODES = {node.id: node for node in (
    n("preflight", "router", "orchestrator", "gpt-5.6-luna", "high", "read", "classify risk with written evidence", outputs=("risk", "approval_required")),
    n("L1", "validator", "orchestrator", "gpt-5.6-luna", "high", "read", "inspect affected flow and establish baseline", outputs=("baseline",)),
    n("L2", "agent", "orchestrator", "gpt-5.6-luna", "high", "read", "define bounded change and acceptance evidence", ("baseline",), ("acceptance",)),
    n("L3", "agent", "implementer", "gpt-5.6-terra", "medium", "write", "implement and test the low-risk change", ("acceptance",), ("source_change",), output_revision="implementation", idempotency="reconcile-before-reapply"),
    n("L4", "validator", "orchestrator", "gpt-5.6-luna", "high", "commit", "verify, create atomic commits, and report", ("source_change",), input_revision="implementation"),
    n("T1", "validator", "orchestrator", "gpt-5.6-luna", "xhigh", "read", "record risk classification and establish baseline", outputs=("baseline",)),
    n("T2", "agent", "orchestrator", "gpt-5.6-luna", "xhigh", "read", "discover repository and trace affected flow", ("baseline",), ("discovery",)),
    n("T3", "agent", "orchestrator", "gpt-5.6-luna", "xhigh", "read", "define acceptance criteria and non-goals", ("discovery",), ("acceptance",)),
    n("T4", "agent", "orchestrator", "gpt-5.6-luna", "xhigh", "read", "produce implementation and atomic commit plan", ("acceptance",), ("plan",)),
    n("approval-router", "router", "orchestrator", "gpt-5.6-luna", "high", "none", "route required plan approval", ("plan",)),
    n("astra-plan", "agent", "escalation-reviewer", "gpt-6-astra", "high", "read", "independently adjudicate high-risk or ambiguous plan", ("plan",), ("judgment",)),
    n("T5", "human-gate", "human", "human", "n/a", "human", "approve, revise, reject, or abort plan", ("plan", "judgment")),
    n("T6", "agent", "implementer", "gpt-5.6-terra", "high", "write", "implement approved change and focused tests", ("plan",), ("source_change",), output_revision="implementation", idempotency="reconcile-before-reapply"),
    n("review-fanout", "fan-out", "orchestrator", "gpt-5.6-luna", "high", "none", "run ordinary and adversarial reviews", ("source_change",)),
    n("T7", "review", "reviewer", "gpt-5.6-sol", "medium", "read", "ordinary review of diff and proposed commit plan", ("source_change",), input_revision="implementation"),
    n("T8", "review", "adversarial-reviewer", "gpt-5.6-sol", "medium", "read", "try to disprove the implementation", ("source_change",), input_revision="implementation"),
    n("review-join", "join", "orchestrator", "gpt-5.6-luna", "xhigh", "none", "join same-revision reviews and evaluate progress", ("T7", "T8"), input_revision="implementation"),
    n("astra-adjudication", "agent", "escalation-reviewer", "gpt-6-astra", "high", "read", "adjudicate material reviewer disagreement", ("T7", "T8"), input_revision="implementation"),
    n("T9", "validator", "acceptance-verifier", "gpt-5.6-sol", "medium", "read", "run repository validation", ("review-join",), input_revision="implementation"),
    n("T10", "validator", "acceptance-verifier", "gpt-5.6-sol", "medium", "read", "run real focused acceptance scenario", ("T9",), input_revision="implementation"),
    n("T11", "agent", "implementer", "gpt-5.6-terra", "high", "write", "resolve only must-fix findings", ("findings",), output_revision="implementation", idempotency="reconcile-before-reapply"),
    n("human-waiver", "human-gate", "human", "human", "n/a", "human", "explicitly waive missing acceptance path", ("T10",)),
    n("T12", "validator", "orchestrator", "gpt-5.6-luna", "max", "commit", "construct and verify atomic commits and committed HEAD", ("T10",), input_revision="implementation"),
    n("T13", "validator", "orchestrator", "gpt-5.6-luna", "max", "read", "audit task list and definition of done", ("T12",), input_revision="implementation"),
    n("human-gate", "human-gate", "human", "human", "n/a", "human", "resolve blocker, conflict, or no-progress condition"),
    n("merge-ready", "terminal", "orchestrator", "gpt-5.6-luna", "high", "none", "mark the run merge-ready"),
    n("awaiting-human", "terminal", "orchestrator", "gpt-5.6-luna", "high", "none", "wait without concealing unresolved state"),
    n("aborted", "terminal", "orchestrator", "gpt-5.6-luna", "high", "none", "abort while preserving evidence"),
)}


EDGES = (
    Edge("preflight", "low", "L1"), Edge("preflight", "medium", "T1"), Edge("preflight", "high", "T1"),
    Edge("L1", "pass", "L2"), Edge("L1", "baseline-fail", "human-gate"), Edge("L2", "pass", "L3"),
    Edge("L3", "pass", "L4"), Edge("L4", "pass", "merge-ready"),
    Edge("T1", "pass", "T2"), Edge("T1", "baseline-fail", "human-gate"), Edge("T2", "pass", "T3"),
    Edge("T3", "pass", "T4"), Edge("T4", "pass", "approval-router"),
    Edge("approval-router", "required", "astra-plan"), Edge("approval-router", "not-required", "T6"),
    Edge("astra-plan", "pass", "T5"), Edge("T5", "approved", "T6"), Edge("T5", "revise", "T3"),
    Edge("T5", "rejected", "awaiting-human"), Edge("T5", "abort", "aborted"),
    Edge("T6", "pass", "review-fanout"), Edge("review-fanout", "ordinary", "T7"),
    Edge("review-fanout", "adversarial", "T8"), Edge("T7", "complete", "review-join"),
    Edge("T8", "complete", "review-join"),
    Edge("review-join", "must-fix", "T11"), Edge("review-join", "conflict", "astra-adjudication"),
    Edge("review-join", "no-progress", "human-gate"), Edge("review-join", "clean", "T9"),
    Edge("astra-adjudication", "resolved-clean", "T9"), Edge("astra-adjudication", "resolved-must-fix", "T11"),
    Edge("astra-adjudication", "human-required", "human-gate"), Edge("T11", "pass", "review-fanout"),
    Edge("T9", "pass", "T10"), Edge("T9", "actionable-failure", "T11"), Edge("T9", "blocker", "human-gate"),
    Edge("T10", "pass", "T12"), Edge("T10", "fail", "human-gate"), Edge("T10", "waiver-required", "human-waiver"),
    Edge("human-waiver", "approved", "T12"), Edge("human-waiver", "rejected", "awaiting-human"),
    Edge("T12", "pass", "T13"), Edge("T13", "pass", "merge-ready"),
    Edge("human-gate", "resume", "T1"), Edge("human-gate", "revise", "T3"),
    Edge("human-gate", "rejected", "awaiting-human"), Edge("human-gate", "abort", "aborted"),
    *(Edge(node, "blocked", "human-gate") for node in sorted(HOOK_NODES)),
)


SUCCESS_OUTCOMES = {"low", "medium", "high", "pass", "required", "not-required", "approved",
                    "clean", "resolved-clean", "joined", "resume"}


def _complete_node_metadata() -> None:
    """Fill route metadata from the canonical edge table before it is fingerprinted."""
    for node_id, node in tuple(NODES.items()):
        edges = tuple(edge for edge in EDGES if edge.source == node_id)
        success = tuple(f"{edge.outcome}->{edge.target}" for edge in edges if edge.outcome in SUCCESS_OUTCOMES)
        failure = tuple(f"{edge.outcome}->{edge.target}" for edge in edges if edge.outcome not in SUCCESS_OUTCOMES)
        preconditions = ("run_status=running",) + tuple(f"input:{item}" for item in node.required_inputs)
        NODES[node_id] = Node(**{**asdict(node), "preconditions": preconditions,
                                 "success_route": success, "failure_route": failure})


_complete_node_metadata()


def graph_fingerprint() -> str:
    payload = repr(([(k, asdict(NODES[k])) for k in sorted(NODES)], [asdict(e) for e in EDGES]))
    return hashlib.sha256(payload.encode()).hexdigest()


def default_state_path(task_id: str) -> Path:
    key = hashlib.sha256(task_id.encode()).hexdigest()
    root = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return root / "agent-workflows" / key / "workflow.db"


def _sanitized(value: Any, key: str = "") -> Any:
    """Redact common secret-bearing fields before durable persistence."""
    if any(part in key.lower() for part in SENSITIVE_KEY_PARTS):
        return "[REDACTED]"
    if isinstance(value, str):
        value = SECRET_VALUE.sub(r"\1[REDACTED]", value)
        return BEARER_VALUE.sub(r"\1[REDACTED]", value)
    if isinstance(value, dict):
        return {k: _sanitized(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitized(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_sanitized(item) for item in value)
    return value


def _encode(value: Any) -> str:
    return repr(_sanitized(value))


def _decode(value: str, default: Any) -> Any:
    try:
        return literal_eval(value)
    except (ValueError, SyntaxError):
        return default


def _bounded(value: Any) -> Any:
    value = _sanitized(value)
    if len(_encode(value).encode()) <= MAX_EVIDENCE_BYTES:
        return value
    if isinstance(value, dict) and value.get("digest") and (value.get("reference") or value.get("artifact_reference")):
        return {key: value[key] for key in ("digest", "reference", "artifact_reference") if key in value}
    raise ValueError("evidence exceeds 64 KiB; provide a digest and artifact reference")


class Agent:
    def __init__(self, node_id: str): self.node_id = node_id

    def run(self, context: Context, state: State, attempt: int) -> Result:
        if self.node_id in HOOK_NODES:
            return Result(self.node_id, attempt, state.task_id, state.context_revision,
                          state.implementation_revision, "blocked",
                          evidence=({"reason": "executor is required", "node_id": self.node_id},),
                          scope_hash=state.scope_hash)
        node, status, evidence = NODES[self.node_id], "pass", ({"action": NODES[self.node_id].action},)
        if self.node_id in {"L1", "T1"} and not context.baseline_passed:
            status, evidence = "fail", ({"baseline": "failed"},)
        if self.node_id == "T10" and not context.acceptance_path:
            status, evidence = "blocked", ({"acceptance_path": "unavailable"},)
        return Result(self.node_id, attempt, state.task_id, state.context_revision,
                      state.implementation_revision, status, evidence=evidence, scope_hash=state.scope_hash)


class PreflightAgent(Agent):
    def run(self, context: Context, state: State, attempt: int) -> Result:
        risk = context.risk if context.risk in RISK_LEVELS else "medium"
        context.risk = risk
        context.approval_required = risk == "high" or context.ambiguity
        return Result(self.node_id, attempt, state.task_id, state.context_revision,
                      state.implementation_revision, "pass",
                      evidence=({"risk": risk, "approval_required": context.approval_required},), scope_hash=state.scope_hash)


ReviewCallback = Callable[[Context], str | tuple[str, Iterable[str]]]


class ReviewAgent(Agent):
    def __init__(self, node_id: str, review: ReviewCallback | None = None):
        super().__init__(node_id); self.review = review or (lambda _context: "clean")

    def run(self, context: Context, state: State, attempt: int) -> Result:
        response = self.review(context)
        outcome, findings = (response, ()) if isinstance(response, str) else response
        findings = tuple(findings)
        context.review_results.append({"node_id": self.node_id, "outcome": outcome,
            "findings": list(findings), "implementation_revision": state.implementation_revision,
            "scope_hash": state.scope_hash})
        return Result(self.node_id, attempt, state.task_id, state.implementation_revision,
                      state.implementation_revision, "pass", evidence=({"outcome": outcome},), findings=findings, scope_hash=state.scope_hash)


class Orchestrator:
    """Sole graph controller, task-state authority, and durable recorder."""

    def __init__(self, task_id: str, store: Path | None = None, budget: Budget | None = None,
                 scope_manifest: ScopeManifest | None = None, manifest: ScopeManifest | None = None,
                 executors: dict[str, Callable[..., Any]] | None = None, lease_ttl: float = 60.0):
        if scope_manifest and manifest and scope_manifest != manifest: raise ValueError("scope manifests disagree")
        self.task_id = task_id
        self.state = State(task_id, graph_fingerprint=graph_fingerprint())
        self._supplied_scope_manifest = scope_manifest or manifest
        self.context, self.store, self.budget = Context(task_id, scope_manifest=self._supplied_scope_manifest), (store or default_state_path(task_id)).expanduser().resolve(), budget or Budget()
        self.lease_ttl, self._owner, self.executors = lease_ttl, uuid.uuid4().hex, executors or {}
        source_root = Path(__file__).resolve().parent
        if self.store == source_root or source_root in self.store.parents: raise ValueError("durable workflow state must live outside the source tree")
        self._approval_token = None
        self._counts = {key: 0 for key in ("evidence", "transitions", "reviews", "cycles", "risks", "waivers", "commits")}
        self.agents = {i: Agent(i) for i, node in NODES.items() if node.type not in {"terminal", "human-gate"}}
        self.agents["preflight"], self.agents["T7"], self.agents["T8"] = PreflightAgent("preflight"), ReviewAgent("T7"), ReviewAgent("T8")
        self.attempts: dict[str, int] = {}
        self._approval_token: str | None = None

        self._init_or_load()

    @classmethod
    def resume(cls, store: Path, scope_manifest: ScopeManifest | None = None,
               executors: dict[str, Callable[..., Any]] | None = None) -> "Orchestrator":
        try:
            conn = sqlite3.connect(Path(store)); row = conn.execute("SELECT task_id FROM runs LIMIT 1").fetchone()
        except sqlite3.DatabaseError as exc: raise ValueError("store is not a workflow SQLite database") from exc
        finally:
            if "conn" in locals(): conn.close()
        if not row: raise ValueError("workflow store has no run")
        return cls(row[0], Path(store), scope_manifest=scope_manifest, executors=executors)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.store, timeout=5, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL"); conn.execute("PRAGMA foreign_keys=ON"); conn.execute("PRAGMA busy_timeout=5000")
        conn.row_factory = sqlite3.Row
        return conn

    def _verify_lease(self, conn: sqlite3.Connection) -> None:
        row = conn.execute("SELECT lease_owner,lease_until FROM runs WHERE task_id=?", (self.state.task_id,)).fetchone()
        if not row or row["lease_owner"] != self._owner or (row["lease_until"] or 0) < time.time(): raise LeaseError("run lease is not owned by this orchestrator")
        conn.execute("UPDATE runs SET lease_until=? WHERE task_id=? AND lease_owner=?", (time.time() + self.lease_ttl, self.state.task_id, self._owner))

    @contextmanager
    def _transaction(self):
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE"); self._verify_lease(conn); yield conn; conn.commit()
        except BaseException:
            conn.rollback(); raise
        finally: conn.close()

    def _schema(self, conn: sqlite3.Connection) -> None:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS runs(task_id TEXT PRIMARY KEY,context_revision INTEGER,task_list_revision INTEGER,implementation_revision INTEGER,intended_diff_hash TEXT,current_node TEXT,status TEXT,risk TEXT,approval_required INTEGER,graph_fingerprint TEXT,scope_hash TEXT,request_hash TEXT,ambiguity INTEGER,baseline_passed INTEGER,acceptance_path INTEGER,waiver INTEGER,changed_source INTEGER,findings TEXT,lease_owner TEXT,lease_until REAL,max_node_attempts INTEGER,max_transitions INTEGER,max_parallel INTEGER,max_review_cycles INTEGER);
        CREATE TABLE IF NOT EXISTS scope_manifests(task_id TEXT PRIMARY KEY REFERENCES runs(task_id) ON DELETE CASCADE,revision TEXT,validation_mode TEXT,manifest_hash TEXT);
        CREATE TABLE IF NOT EXISTS scope_items(task_id TEXT REFERENCES runs(task_id) ON DELETE CASCADE,kind TEXT,ordinal INTEGER,value TEXT,PRIMARY KEY(task_id,kind,ordinal));
        CREATE TABLE IF NOT EXISTS tasks(task_id TEXT REFERENCES runs(task_id) ON DELETE CASCADE,id TEXT,description TEXT,goal TEXT,owner TEXT,status TEXT,dependencies TEXT,acceptance_evidence TEXT,affected TEXT,reason TEXT,next_action TEXT,PRIMARY KEY(task_id,id));
        CREATE TABLE IF NOT EXISTS node_states(task_id TEXT REFERENCES runs(task_id) ON DELETE CASCADE,node_id TEXT,status TEXT,output TEXT,PRIMARY KEY(task_id,node_id));
        CREATE TABLE IF NOT EXISTS node_attempts(task_id TEXT REFERENCES runs(task_id) ON DELETE CASCADE,node_id TEXT,attempts INTEGER,PRIMARY KEY(task_id,node_id));
        CREATE TABLE IF NOT EXISTS evidence(task_id TEXT REFERENCES runs(task_id) ON DELETE CASCADE,sequence INTEGER,node_id TEXT,scope TEXT,scope_hash TEXT,implementation_revision INTEGER,payload TEXT,PRIMARY KEY(task_id,sequence));
        CREATE TABLE IF NOT EXISTS transitions(task_id TEXT REFERENCES runs(task_id) ON DELETE CASCADE,sequence INTEGER,event TEXT,current_node TEXT,run_status TEXT,context_revision INTEGER,task_list_revision INTEGER,implementation_revision INTEGER,data TEXT,PRIMARY KEY(task_id,sequence));
        CREATE TABLE IF NOT EXISTS reviews(task_id TEXT REFERENCES runs(task_id) ON DELETE CASCADE,sequence INTEGER,node_id TEXT,outcome TEXT,findings TEXT,implementation_revision INTEGER,scope_hash TEXT,PRIMARY KEY(task_id,sequence));
        CREATE TABLE IF NOT EXISTS review_cycles(task_id TEXT REFERENCES runs(task_id) ON DELETE CASCADE,sequence INTEGER,data TEXT,PRIMARY KEY(task_id,sequence));
        CREATE TABLE IF NOT EXISTS gates(task_id TEXT PRIMARY KEY REFERENCES runs(task_id) ON DELETE CASCADE,gate_id TEXT,token_hash TEXT,graph_fingerprint TEXT,implementation_revision INTEGER,scope_hash TEXT,reason TEXT,resume_node TEXT);
        CREATE TABLE IF NOT EXISTS accepted_risks(task_id TEXT REFERENCES runs(task_id) ON DELETE CASCADE,sequence INTEGER,data TEXT,PRIMARY KEY(task_id,sequence));
        CREATE TABLE IF NOT EXISTS waivers(task_id TEXT REFERENCES runs(task_id) ON DELETE CASCADE,sequence INTEGER,data TEXT,PRIMARY KEY(task_id,sequence));
        CREATE TABLE IF NOT EXISTS commits(task_id TEXT REFERENCES runs(task_id) ON DELETE CASCADE,sequence INTEGER,data TEXT,PRIMARY KEY(task_id,sequence));
        """)

    def _init_or_load(self) -> None:
        self.store.parent.mkdir(parents=True, exist_ok=True, mode=0o700); self.store.parent.chmod(0o700)
        conn = self._connect()
        try:
            self._schema(conn); row = conn.execute("SELECT * FROM runs WHERE task_id=?", (self.state.task_id,)).fetchone()
            if row: self._load(conn, row)
            else:
                if not self.context.scope_manifest: raise ValueError("scope_manifest is required for a new run")
                manifest = self.context.scope_manifest
                conn.execute("INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (self.state.task_id,0,0,0,"","preflight","running","unknown",0,graph_fingerprint(),manifest.hash,"",0,1,1,0,0,"[]",None,None,self.budget.max_node_attempts,self.budget.max_transitions,self.budget.max_parallel,self.budget.max_review_cycles))
                conn.execute("INSERT INTO scope_manifests VALUES (?,?,?,?)", (self.state.task_id,manifest.revision,manifest.validation_mode,manifest.hash))
                conn.executemany("INSERT INTO scope_items VALUES (?,?,?,?)", [(self.state.task_id,"file",i,v) for i,v in enumerate(manifest.changed_files)]+[(self.state.task_id,"target",i,v) for i,v in enumerate(manifest.affected_targets)])
                self.state.scope_hash = manifest.hash
            conn.commit()
        finally: conn.close()
        os.chmod(self.store, 0o600)
        self._claim_lease()
        if self.state.graph_fingerprint != graph_fingerprint(): raise StaleResultError("stored workflow graph fingerprint differs")
        if self._supplied_scope_manifest and self._supplied_scope_manifest.hash != self.state.scope_hash: raise StaleResultError("provided scope manifest differs")

    def _claim_lease(self) -> None:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE"); now = time.time()
            changed = conn.execute("UPDATE runs SET lease_owner=?,lease_until=? WHERE task_id=? AND (lease_owner IS NULL OR lease_until<? OR lease_owner=?)", (self._owner,now+self.lease_ttl,self.state.task_id,now,self._owner)).rowcount
            if changed != 1: conn.rollback(); raise LeaseError("run is already leased by another orchestrator")
            conn.commit()
        finally: conn.close()

    def close(self) -> None:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE"); conn.execute("UPDATE runs SET lease_owner=NULL,lease_until=NULL WHERE task_id=? AND lease_owner=?", (self.state.task_id,self._owner)); conn.commit()
        finally: conn.close()

    def _load(self, conn: sqlite3.Connection, row: sqlite3.Row) -> None:
        m = conn.execute("SELECT * FROM scope_manifests WHERE task_id=?", (self.state.task_id,)).fetchone(); items = conn.execute("SELECT kind,value FROM scope_items WHERE task_id=? ORDER BY kind,ordinal", (self.state.task_id,)).fetchall()
        manifest = ScopeManifest(m["revision"], tuple(x["value"] for x in items if x["kind"]=="file"), tuple(x["value"] for x in items if x["kind"]=="target"), m["validation_mode"])
        self.context = Context(self.state.task_id,risk=row["risk"],ambiguity=bool(row["ambiguity"]),approval_required=bool(row["approval_required"]),baseline_passed=bool(row["baseline_passed"]),acceptance_path=bool(row["acceptance_path"]),waiver=bool(row["waiver"]),findings=list(_decode(row["findings"],[])),changed_source=bool(row["changed_source"]),scope_manifest=manifest)
        self.budget = Budget(row["max_node_attempts"],row["max_transitions"],row["max_parallel"],row["max_review_cycles"])
        self.state = State(self.state.task_id,row["context_revision"],row["task_list_revision"],row["implementation_revision"],row["intended_diff_hash"],row["current_node"],row["status"],row["risk"],bool(row["approval_required"]),row["graph_fingerprint"],row["scope_hash"])
        self.state.tasks = {r["id"]:Task(r["id"],r["description"],r["goal"],r["owner"],r["status"],list(_decode(r["dependencies"],[])),list(_decode(r["acceptance_evidence"],[])),list(_decode(r["affected"],[])),r["reason"],r["next_action"]) for r in conn.execute("SELECT * FROM tasks WHERE task_id=?",(self.state.task_id,))}
        self.state.node_states = {r["node_id"]:r["status"] for r in conn.execute("SELECT * FROM node_states WHERE task_id=?",(self.state.task_id,))}; self.state.node_outputs = {r["node_id"]:_decode(r["output"],{}) for r in conn.execute("SELECT * FROM node_states WHERE task_id=?",(self.state.task_id,))}
        self.state.evidence = [{"node_id":r["node_id"],"scope":r["scope"],"scope_hash":r["scope_hash"],"implementation_revision":r["implementation_revision"],"payload":_decode(r["payload"],{})} for r in conn.execute("SELECT * FROM evidence WHERE task_id=? ORDER BY sequence",(self.state.task_id,))]
        self.state.transitions = [{"sequence":r["sequence"],"event":r["event"],"current_node":r["current_node"],"run_status":r["run_status"],"context_revision":r["context_revision"],"task_list_revision":r["task_list_revision"],"implementation_revision":r["implementation_revision"],"data":_decode(r["data"],{})} for r in conn.execute("SELECT * FROM transitions WHERE task_id=? ORDER BY sequence",(self.state.task_id,))]
        self.context.review_results = [{"node_id":r["node_id"],"outcome":r["outcome"],"findings":list(_decode(r["findings"],[])),"implementation_revision":r["implementation_revision"],"scope_hash":r["scope_hash"]} for r in conn.execute("SELECT * FROM reviews WHERE task_id=? ORDER BY sequence",(self.state.task_id,))]
        self.state.review_cycles=[dict(_decode(r["data"],{})) for r in conn.execute("SELECT * FROM review_cycles WHERE task_id=? ORDER BY sequence",(self.state.task_id,))]; self.state.accepted_risks=[dict(_decode(r["data"],{})) for r in conn.execute("SELECT * FROM accepted_risks WHERE task_id=? ORDER BY sequence",(self.state.task_id,))]; self.state.waivers=[dict(_decode(r["data"],{})) for r in conn.execute("SELECT * FROM waivers WHERE task_id=? ORDER BY sequence",(self.state.task_id,))]; self.state.commits=[dict(_decode(r["data"],{})) for r in conn.execute("SELECT * FROM commits WHERE task_id=? ORDER BY sequence",(self.state.task_id,))]
        gate=conn.execute("SELECT * FROM gates WHERE task_id=?",(self.state.task_id,)).fetchone(); self.state.pending_gate=dict(gate) if gate else None
        if self.state.pending_gate: self.state.pending_gate.pop("task_id",None)
        self.attempts={r["node_id"]:r["attempts"] for r in conn.execute("SELECT * FROM node_attempts WHERE task_id=?",(self.state.task_id,))}; self._counts={"evidence":len(self.state.evidence),"transitions":len(self.state.transitions),"reviews":len(self.context.review_results),"cycles":len(self.state.review_cycles),"risks":len(self.state.accepted_risks),"waivers":len(self.state.waivers),"commits":len(self.state.commits)}

    def _load_from_db(self) -> None:
        conn=self._connect()
        try: self._load(conn,conn.execute("SELECT * FROM runs WHERE task_id=?",(self.state.task_id,)).fetchone())
        finally: conn.close()

    def checkpoint(self, event: str, data: dict[str, Any] | None = None) -> None:
        if len(self.state.transitions) >= self.budget.max_transitions: raise RuntimeError("transition budget exhausted")
        transition={"sequence":len(self.state.transitions)+1,"event":event,"current_node":self.state.current_node,"run_status":self.state.status,"context_revision":self.state.context_revision,"task_list_revision":self.state.task_list_revision,"implementation_revision":self.state.implementation_revision,"data":_bounded(data or {})}; self.state.transitions.append(transition); source=self.context.source_text; token=self._approval_token
        try:
            with self._transaction() as conn:
                conn.execute("UPDATE runs SET context_revision=?,task_list_revision=?,implementation_revision=?,intended_diff_hash=?,current_node=?,status=?,risk=?,approval_required=?,scope_hash=?,request_hash=?,ambiguity=?,baseline_passed=?,acceptance_path=?,waiver=?,changed_source=?,findings=? WHERE task_id=?",(self.state.context_revision,self.state.task_list_revision,self.state.implementation_revision,self.state.intended_diff_hash,self.state.current_node,self.state.status,self.state.risk,int(self.state.approval_required),self.state.scope_hash,hashlib.sha256(self.context.request.encode()).hexdigest() if self.context.request else "",int(self.context.ambiguity),int(self.context.baseline_passed),int(self.context.acceptance_path),int(self.context.waiver),int(self.context.changed_source),_encode(self.context.findings),self.state.task_id))
                for t in self.state.tasks.values(): conn.execute("INSERT OR REPLACE INTO tasks VALUES (?,?,?,?,?,?,?,?,?,?,?)",(self.state.task_id,t.id,t.description,t.goal,t.owner,t.status,_encode(t.dependencies),_encode(t.acceptance_evidence),_encode(t.affected_files_or_subsystem),t.reason,t.next_action))
                for node,status in self.state.node_states.items(): conn.execute("INSERT OR REPLACE INTO node_states VALUES (?,?,?,?)",(self.state.task_id,node,status,_encode(self.state.node_outputs.get(node,{}))))
                nodes = tuple(self.state.node_states)
                if nodes:
                    marks = ",".join("?" for _ in nodes)
                    conn.execute(f"DELETE FROM node_states WHERE task_id=? AND node_id NOT IN ({marks})", (self.state.task_id, *nodes))
                else: conn.execute("DELETE FROM node_states WHERE task_id=?", (self.state.task_id,))
                for node,attempts in self.attempts.items(): conn.execute("INSERT OR REPLACE INTO node_attempts VALUES (?,?,?)",(self.state.task_id,node,attempts))
                if len(self.state.evidence)<self._counts["evidence"]: conn.execute("DELETE FROM evidence WHERE task_id=?",(self.state.task_id,)); self._counts["evidence"]=0
                if len(self.context.review_results)<self._counts["reviews"]: conn.execute("DELETE FROM reviews WHERE task_id=?",(self.state.task_id,)); self._counts["reviews"]=0
                for i in range(self._counts["evidence"],len(self.state.evidence)):
                    e=self.state.evidence[i]; conn.execute("INSERT INTO evidence VALUES (?,?,?,?,?,?,?)",(self.state.task_id,i+1,e["node_id"],e["scope"],e["scope_hash"],e["implementation_revision"],_encode(e["payload"])))
                for i in range(self._counts["transitions"],len(self.state.transitions)):
                    t=self.state.transitions[i]; conn.execute("INSERT INTO transitions VALUES (?,?,?,?,?,?,?,?,?)",(self.state.task_id,t["sequence"],t["event"],t["current_node"],t["run_status"],t["context_revision"],t["task_list_revision"],t["implementation_revision"],_encode(t["data"])))
                for i in range(self._counts["reviews"],len(self.context.review_results)):
                    r=self.context.review_results[i]; conn.execute("INSERT INTO reviews VALUES (?,?,?,?,?,?,?)",(self.state.task_id,i+1,r["node_id"],r["outcome"],_encode(r["findings"]),r["implementation_revision"],r.get("scope_hash",self.state.scope_hash)))
                for key,table,values in (("cycles","review_cycles",self.state.review_cycles),("risks","accepted_risks",self.state.accepted_risks),("waivers","waivers",self.state.waivers),("commits","commits",self.state.commits)):
                    for i in range(self._counts[key],len(values)): conn.execute(f"INSERT INTO {table} VALUES (?,?,?)",(self.state.task_id,i+1,_encode(values[i])))
                if self.state.pending_gate:
                    g=self.state.pending_gate; conn.execute("INSERT OR REPLACE INTO gates VALUES (?,?,?,?,?,?,?,?)",(self.state.task_id,g["gate_id"],g["token_hash"],g["graph_fingerprint"],g["implementation_revision"],g["scope_hash"],g["reason"],g.get("resume_node")))
                else: conn.execute("DELETE FROM gates WHERE task_id=?",(self.state.task_id,))
            self._counts={"evidence":len(self.state.evidence),"transitions":len(self.state.transitions),"reviews":len(self.context.review_results),"cycles":len(self.state.review_cycles),"risks":len(self.state.accepted_risks),"waivers":len(self.state.waivers),"commits":len(self.state.commits)}; os.chmod(self.store,0o600)
        except BaseException:
            self._load_from_db(); self.context.source_text=source; self._approval_token=token; raise

    def _revision(self, name: str) -> int:
        return {"context": self.state.context_revision, "task_list": self.state.task_list_revision,
                "implementation": self.state.implementation_revision}[name]

    def _create_task(self, task_id: str, description: str, goal: str, owner: str,
                     dependencies: Iterable[str] = (), affected: Iterable[str] = ()) -> None:
        if task_id in self.state.tasks: raise ValueError(f"task already exists: {task_id}")
        dependencies = list(dependencies)
        if unknown := [d for d in dependencies if d not in self.state.tasks]: raise ValueError(f"unknown dependencies: {unknown}")
        self.state.tasks[task_id] = Task(task_id, description, goal, owner,
            dependencies=dependencies, affected_files_or_subsystem=list(affected))
        self.state.task_list_revision += 1

    def create_task(self, task_id: str, description: str, goal: str, owner: str,
                    dependencies: Iterable[str] = (), affected: Iterable[str] = ()) -> None:
        self._create_task(task_id, description, goal, owner, dependencies, affected)
        self.checkpoint("task-created", {"task_id": task_id})

    def _update_task(self, task_id: str, status: str, evidence: Iterable[dict[str, Any]] = (),
                     reason: str = "", next_action: str = "") -> None:
        if status not in TASK_STATUSES: raise ValueError(f"unknown task status: {status}")
        task, evidence = self.state.tasks[task_id], [_bounded(item) for item in evidence]
        legal = {"pending": {"pending", "active", "done", "cancelled"}, "active": {"active", "done", "blocked", "failed", "cancelled"},
                 "blocked": {"blocked", "active", "done", "cancelled"}, "failed": {"failed", "active", "cancelled"},
                 "cancelled": {"cancelled", "pending"}, "done": {"done"}}
        if status not in legal[task.status]: raise ValueError(f"illegal task transition {task.status}->{status}")
        if status == "active" and (incomplete := [d for d in task.dependencies if self.state.tasks[d].status != "done"]):
            raise ValueError(f"task {task_id} has incomplete dependencies: {incomplete}")
        if status == "done" and not evidence and not task.acceptance_evidence: raise ValueError("done requires evidence")
        if status in {"blocked", "failed", "cancelled"} and not reason: raise ValueError(f"{status} requires a reason")
        if status in {"blocked", "failed"} and not next_action: raise ValueError(f"{status} requires a next action")
        task.status, task.reason, task.next_action = status, reason, next_action
        task.acceptance_evidence.extend(evidence); self.state.task_list_revision += 1

    def update_task(self, task_id: str, status: str, evidence: Iterable[dict[str, Any]] = (),
                    reason: str = "", next_action: str = "") -> None:
        self._update_task(task_id, status, evidence, reason, next_action)
        self.checkpoint("task-updated", {"task_id": task_id, "status": status})

    def _bootstrap_tasks(self, risk: str) -> None:
        ids = ["L1", "L2", "L3", "L4"] if risk == "low" else [f"T{i}" for i in range(1, 14)]
        dependencies = {
            "L1": [], "L2": ["L1"], "L3": ["L2"], "L4": ["L3"],
            "T1": [], "T2": ["T1"], "T3": ["T2"], "T4": ["T3"],
            "T5": ["T4"], "T6": ["T5"] if self.state.approval_required else ["T4"],
            "T7": ["T6"], "T8": ["T6"], "T9": ["T7", "T8"],
            "T10": ["T9"], "T11": ["T7", "T8"], "T12": ["T10"], "T13": ["T12"],
        }
        for node_id in ids:
            if node_id in self.state.tasks: continue
            self._create_task(node_id, NODES[node_id].action, NODES[node_id].action,
                             NODES[node_id].owner, dependencies[node_id])
        if risk != "low" and not self.state.approval_required:
            self._update_task("T5", "cancelled", reason="plan approval is not required for an unambiguous medium-risk run")

    def activate(self, node_id: str | None = None) -> Result:
        node_id = node_id or self.state.current_node
        if self.state.status != "running": raise ValueError(f"run is not active: {self.state.status}")
        if node_id != self.state.current_node: raise ValueError(f"only current node may run: {self.state.current_node}")
        if self.state.node_states.get(node_id) == "done": raise ValueError(f"node already completed: {node_id}")
        if node_id in HUMAN_NODES or NODES[node_id].type == "terminal": raise ValueError(f"{node_id} requires routing or human decision")
        self.checkpoint(f"before:{node_id}")
        attempt = self.attempts.get(node_id, 0) + 1
        if attempt > self.budget.max_node_attempts: self.pause(f"attempt budget exhausted for {node_id}", node_id); raise RuntimeError("attempt budget exhausted")
        self.attempts[node_id] = attempt
        if node_id in self.state.tasks: self._update_task(node_id, "active")
        result = self._normalize(self._execute(node_id, attempt))
        if node_id in WRITE_NODES and result.status == "pass":
            if not self.context.source_text:
                raise ValueError(f"{node_id} must provide source_text before changing implementation")
            self.bump_implementation_revision(self.context.source_text)
            result = Result(result.node_id, result.attempt, result.task_id, result.input_revision,
                self.state.implementation_revision, result.status, result.evidence, result.findings,
                result.uncertainties, result.recommended_next_action, self.state.scope_hash)
        self._record(result)
        if node_id == "preflight":
            self.state.risk, self.state.approval_required = self.context.risk, self.context.approval_required
        if NODES[node_id].output_revision == "context": self.state.context_revision += 1
        if node_id in self.state.tasks:
            if result.status == "pass": self._update_task(node_id, "done", result.evidence)
            else: self._update_task(node_id, "failed" if result.status == "fail" else "blocked",
                reason=f"{node_id} returned {result.status}", next_action="route to human or repair gate")
        self.state.node_states[node_id] = "done" if result.status == "pass" else result.status
        self.checkpoint(f"after:{node_id}", {"result_status": result.status}); return result

    def _run_agent(self, node_id: str) -> Result:
        attempt = self.attempts.get(node_id, 0) + 1
        if attempt > self.budget.max_node_attempts: raise RuntimeError(f"attempt budget exhausted for {node_id}")
        self.attempts[node_id] = attempt
        if node_id in self.state.tasks: self._update_task(node_id, "active")
        result = self._normalize(self._execute(node_id, attempt)); self._record(result)
        if node_id in self.state.tasks: self._update_task(node_id, "done", result.evidence)
        self.state.node_states[node_id] = "done"; return result

    def _execute(self, node_id: str, attempt: int) -> Result:
        executor = self.executors.get(node_id)
        kind = ("implementation" if node_id in IMPLEMENTATION_NODES else "validation" if node_id in VALIDATION_NODES
                else "acceptance" if node_id in ACCEPTANCE_NODES else "commit" if node_id in COMMIT_NODES else "")
        executor = executor or self.executors.get(kind)
        if not executor: return self.agents[node_id].run(self.context, self.state, attempt)
        response = executor(self.context, self.state, attempt)
        if isinstance(response, Result): return response
        if isinstance(response, str):
            return Result(node_id, attempt, self.task_id, self._revision(NODES[node_id].input_revision), self.state.implementation_revision, response, evidence=(({"status": response},) if response == "pass" else ()), scope_hash=self.state.scope_hash)
        if isinstance(response, dict):
            status = response.get("status", "blocked")
            return Result(node_id, attempt, self.task_id, self._revision(NODES[node_id].input_revision), self.state.implementation_revision, status, tuple(response.get("evidence", ({"status": status},) if status == "pass" else ())), tuple(response.get("findings", ())), scope_hash=response.get("scope_hash", self.state.scope_hash))
        raise TypeError("executor must return Result, status string, or result mapping")

    def _normalize(self, result: Result) -> Result:
        node = NODES[result.node_id]
        if result.task_id != self.state.task_id: raise StaleResultError("result belongs to another run")
        if node.input_revision == "implementation" and result.implementation_revision != self.state.implementation_revision:
            raise StaleResultError(f"{result.node_id} used revision {result.implementation_revision}; current is {self.state.implementation_revision}")
        if result.scope_hash and result.scope_hash != self.state.scope_hash: raise StaleResultError("result targets stale scope")
        evidence = tuple(_bounded(item) for item in result.evidence)
        return Result(result.node_id, result.attempt, result.task_id, self._revision(node.input_revision),
                      result.implementation_revision, result.status, evidence, result.findings,
                      result.uncertainties, result.recommended_next_action, self.state.scope_hash)

    def _record(self, result: Result) -> None:
        self.state.node_outputs[result.node_id] = {"attempt": result.attempt, "status": result.status,
            "implementation_revision": result.implementation_revision, "findings": list(result.findings)}
        scope = "implementation" if NODES[result.node_id].input_revision == "implementation" or result.node_id in WRITE_NODES else "run"
        for item in result.evidence:
            self.state.evidence.append({"node_id": result.node_id, "scope": scope, "scope_hash": self.state.scope_hash,
                "implementation_revision": result.implementation_revision, "payload": item})

    def route(self, outcome: str) -> str:
        source = self.state.current_node
        matches = [e.target for e in EDGES if e.source == source and e.outcome == outcome]
        if len(matches) != 1: raise ValueError(f"expected one route for {source}/{outcome}, found {len(matches)}")
        if NODES[source].type in {"agent", "validator", "review"} and self.state.node_states.get(source) != "done" and outcome in SUCCESS_OUTCOMES | {"complete"}:
            raise ValueError(f"node {source} has not completed")
        if source == "preflight":
            if outcome != self.context.risk: raise ValueError(f"classified {self.context.risk}, not {outcome}")
            self._bootstrap_tasks(outcome)
        if source == "approval-router":
            expected = "required" if self.state.approval_required else "not-required"
            if outcome != expected: raise ValueError(f"approval outcome must be {expected}")
        target = matches[0]
        if target in HUMAN_NODES:
            self.open_gate(target, f"human decision required after {source}", source); return target
        if target == "merge-ready":
            if "T11" in self.state.tasks and self.state.tasks["T11"].status == "pending":
                self._update_task("T11", "cancelled", reason="no must-fix task was required")
            self.final_audit()
        self.state.current_node = target
        if target in {"merge-ready", "awaiting-human", "aborted"}: self.state.status = target
        self.checkpoint(f"route:{source}:{outcome}:{target}"); return target

    def open_gate(self, gate_id: str, reason: str, resume_node: str | None = None) -> str:
        token = secrets.token_urlsafe(24)
        self.state.current_node, self.state.status = gate_id, "awaiting-human"
        self.state.pending_gate = {"gate_id": gate_id, "token_hash": hashlib.sha256(token.encode()).hexdigest(),
            "graph_fingerprint": self.state.graph_fingerprint, "implementation_revision": self.state.implementation_revision,
            "scope_hash": self.state.scope_hash, "reason": reason, "resume_node": resume_node}
        self._approval_token = token
        self.checkpoint(f"gate-opened:{gate_id}", {"reason": reason}); return token

    def take_approval_token(self) -> str:
        """Return a newly opened gate token once; raw tokens are never persisted."""
        if self._approval_token is None: raise ValueError("no new approval token is available")
        token, self._approval_token = self._approval_token, None
        return token

    def reissue_gate(self) -> str:
        """Issue a fresh token after resume without changing the gated state."""
        if not self.state.pending_gate or self.state.status != "awaiting-human":
            raise ValueError("no human gate is pending")
        return self.open_gate(self.state.pending_gate["gate_id"], self.state.pending_gate["reason"], self.state.pending_gate.get("resume_node"))

    def pause(self, reason: str, resume_node: str) -> str:
        token = self.open_gate("human-gate", reason, resume_node)
        self.checkpoint("awaiting-human", {"reason": reason}); return token

    def decide(self, token: str, decision: str) -> str:
        gate = self.state.pending_gate
        if not gate: raise ValueError("no human decision is pending")
        allowed = {"T5": {"approved", "revise", "rejected", "abort"}, "human-waiver": {"approved", "rejected"}, "human-gate": {"resume", "revise", "rejected", "abort"}}.get(gate["gate_id"], set())
        if decision not in allowed: raise ValueError(f"invalid decision for {gate['gate_id']}: {decision}")
        if gate["graph_fingerprint"] != self.state.graph_fingerprint or gate["implementation_revision"] != self.state.implementation_revision or gate.get("scope_hash") != self.state.scope_hash:
            raise StaleResultError("approval is bound to obsolete state")
        if not secrets.compare_digest(gate["token_hash"], hashlib.sha256(token.encode()).hexdigest()):
            raise PermissionError("invalid approval token")
        gate_id = gate["gate_id"]
        self.state.status, self.state.pending_gate = "running", None
        self._approval_token = None
        if gate_id == "T5" and "T5" in self.state.tasks:
            if decision == "approved": self._update_task("T5", "done", ({"human_decision": decision, "scope_hash": self.state.scope_hash},))
            elif decision in {"rejected", "abort"}: self._update_task("T5", "blocked", reason=f"human decision: {decision}", next_action="human must revise or terminate the run")
        if gate_id == "human-waiver" and decision == "approved":
            self.context.waiver = True
            self.state.waivers.append({"kind": "missing-acceptance-path", "approver": "human", "rationale": gate["reason"], "scope_hash": self.state.scope_hash})
            if "T10" in self.state.tasks:
                self._update_task("T10", "done", ({"human_waiver": True, "scope_hash": self.state.scope_hash},))
                self.state.node_states["T10"] = "done"
        if gate_id == "human-gate" and decision == "resume" and gate.get("resume_node"):
            target = gate["resume_node"]
            self.state.current_node = target
            self.checkpoint(f"human-decision:{decision}:{target}")
            return target
        target = self.route(decision); self.checkpoint(f"human-decision:{decision}"); return target

    def run_parallel_reviews(self) -> tuple[Result, Result]:
        if self.state.current_node != "review-fanout": raise ValueError("reviews start only at review-fanout")
        if self.budget.max_parallel < 2: raise RuntimeError("parallel budget does not permit two reviews")
        self.checkpoint("before:review-fanout"); revision = self.state.implementation_revision
        for node_id in REVIEW_NODES:
            if node_id in self.state.tasks: self._update_task(node_id, "active")
            self.attempts[node_id] = self.attempts.get(node_id, 0) + 1
            if self.attempts[node_id] > self.budget.max_node_attempts: raise RuntimeError(f"attempt budget exhausted for {node_id}")
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {node_id: pool.submit(self.agents[node_id].run, self.context, self.state, self.attempts[node_id]) for node_id in REVIEW_NODES}
            results = tuple(self._normalize(futures[node_id].result()) for node_id in ("T7", "T8"))
        for result in results:
            self._record(result); self._update_task(result.node_id, "done", result.evidence)
            self.state.node_states[result.node_id] = "done"
        if any(r.implementation_revision != revision or r.scope_hash != self.state.scope_hash for r in results): raise StaleResultError("reviews target different state")
        self.state.current_node = "review-join"; self.checkpoint("after:review-fanout", {"implementation_revision": revision, "scope_hash": self.state.scope_hash})
        return results

    def join_reviews(self) -> str:
        if self.state.current_node != "review-join": raise ValueError("not at review join")
        current = [r for r in self.context.review_results if r["implementation_revision"] == self.state.implementation_revision and r.get("scope_hash") == self.state.scope_hash]
        if {r["node_id"] for r in current} != REVIEW_NODES: raise StaleResultError("both current-revision reviews are required")
        outcomes, findings = {r["outcome"] for r in current}, sorted({f for r in current for f in r["findings"]})
        if "conflict" in outcomes or len(outcomes) > 1: route = "conflict"
        elif outcomes == {"clean"}: route = "clean"
        else:
            previous, current_set = set(self.state.previous_must_fixes), set(findings)
            resolved, introduced = previous - current_set, current_set - previous
            progress = not previous or (bool(resolved) and len(introduced) < len(resolved))
            route = "must-fix" if progress else "no-progress"
            self.state.previous_must_fixes = findings
            self.state.review_cycles.append({"implementation_revision": self.state.implementation_revision,
                "scope_hash": self.state.scope_hash, "resolved": sorted(resolved), "introduced": sorted(introduced), "progress": progress})
            if self.budget.max_review_cycles is not None and len(self.state.review_cycles) >= self.budget.max_review_cycles:
                route = "no-progress"
        if route == "clean": self.state.previous_must_fixes.clear()
        self.context.findings = findings; self.checkpoint("join:reviews", {"outcome": route, "findings": findings, "scope_hash": self.state.scope_hash}); return route

    def bump_implementation_revision(self, source_text: str = "") -> None:
        if not source_text:
            raise ValueError("source_text is required to recalculate the intended diff hash")
        self.state.implementation_revision += 1
        self.state.intended_diff_hash = hashlib.sha256(source_text.encode()).hexdigest()
        self.state.evidence = [e for e in self.state.evidence if e.get("scope") != "implementation"]
        invalid = REVIEW_NODES | {"review-join", "T9", "T10", "T12", "T13"}
        self.state.node_outputs = {k: v for k, v in self.state.node_outputs.items() if k not in invalid}
        self.state.node_states = {k: v for k, v in self.state.node_states.items() if k not in invalid}
        self.context.review_results.clear()

    def escalate_risk(self, new_risk: str, evidence: str) -> None:
        if new_risk not in RISK_LEVELS: raise ValueError(f"unknown risk: {new_risk}")
        current = self.state.risk if self.state.risk in RISK_LEVELS else "low"
        if RISK_ORDER[new_risk] <= RISK_ORDER[current]: raise ValueError("automatic risk changes may only classify upward")
        if any(task_id.startswith("L") for task_id in self.state.tasks):
            for task in [t for t in self.state.tasks.values() if t.id.startswith("L") and t.status != "done"]:
                self._update_task(task.id, "cancelled", reason=f"superseded by {new_risk}-risk workflow")
        self.state.risk = self.context.risk = new_risk
        self.state.approval_required = self.context.approval_required = new_risk == "high" or self.context.ambiguity
        if "T1" not in self.state.tasks:
            self._bootstrap_tasks(new_risk)
        elif new_risk == "high" and self.state.tasks["T5"].status == "cancelled":
            self._update_task("T5", "pending")
            self.state.tasks["T6"].dependencies = ["T5"]
            self.state.task_list_revision += 1
        self.state.evidence.append({"node_id": "preflight", "scope": "run", "scope_hash": self.state.scope_hash, "implementation_revision": self.state.implementation_revision,
            "payload": {"risk_escalation": evidence}})
        self.state.current_node = "T1"; self.checkpoint("risk-escalated", {"risk": new_risk})

    def final_audit(self) -> None:
        unresolved = [t.id for t in self.state.tasks.values() if t.status not in {"done", "cancelled"}]
        if unresolved: raise ValueError(f"not merge-ready; unresolved tasks: {unresolved}")
        if self.state.pending_gate: raise ValueError("not merge-ready while a gate is pending")
        acceptance_node, commit_node = (("L3", "L4") if self.state.risk == "low" else ("T10", "T12"))
        if self.state.node_states.get(acceptance_node) != "done":
            raise ValueError(f"acceptance validation is incomplete: {acceptance_node}")
        if not any(e["node_id"] == acceptance_node and e.get("scope_hash") == self.state.scope_hash and e["implementation_revision"] == self.state.implementation_revision for e in self.state.evidence):
            raise ValueError("acceptance evidence is stale or missing")
        if self.state.node_states.get(commit_node) != "done" or not self.state.commits:
            raise ValueError(f"commit and HEAD verification is incomplete: {commit_node}")
        if self.state.commits[-1].get("scope_hash") != self.state.scope_hash or self.state.commits[-1].get("implementation_revision") != self.state.implementation_revision:
            raise ValueError("commit evidence is stale")

    def accept_risk(self, rationale: str, impact: str, approver: str, follow_up: str) -> None:
        """Record an explicitly approved risk; high-risk runs require a human."""
        if not all((rationale, impact, approver, follow_up)):
            raise ValueError("accepted risk requires rationale, impact, approver, and follow-up")
        if self.state.risk == "high" and approver != "human":
            raise PermissionError("high-risk exceptions require explicit human acceptance")
        self.state.accepted_risks.append({"rationale": rationale, "impact": impact,
            "approver": approver, "follow_up": follow_up, "scope_hash": self.state.scope_hash})
        self.checkpoint("risk-accepted", {"approver": approver, "impact": impact})

    def record_commit(self, commit_hash: str, command_results: Iterable[str], head_hash: str) -> None:
        """Record commit evidence after the Orchestrator verifies committed HEAD."""
        if not (7 <= len(commit_hash) <= 64 and all(char in "0123456789abcdef" for char in commit_hash.lower())):
            raise ValueError("commit hash must be hexadecimal")
        if head_hash.lower() != commit_hash.lower():
            raise ValueError("committed HEAD does not match the recorded commit")
        command_results = list(command_results)
        if not command_results: raise ValueError("commit evidence requires validation command results")
        if self.state.current_node not in {"L4", "T12"} or self.state.node_states.get(self.state.current_node) != "done":
            raise ValueError("commit evidence can only be recorded after the commit-verification node passes")
        self.state.commits.append({"hash": commit_hash, "head_hash": head_hash, "command_results": command_results,
                                   "implementation_revision": self.state.implementation_revision, "scope_hash": self.state.scope_hash})
        self.checkpoint("commit-recorded", {"hash": commit_hash})

    def final_report(self) -> dict[str, Any]:
        """Return the durable, user-facing completion record."""
        return {
            "risk": self.state.risk,
            "approval_required": self.state.approval_required,
            "run_status": self.state.status,
            "graph_fingerprint": self.state.graph_fingerprint,
            "scope_hash": self.state.scope_hash,
            "scope_manifest": asdict(self.context.scope_manifest) if self.context.scope_manifest else None,
            "context_revision": self.state.context_revision,
            "task_list_revision": self.state.task_list_revision,
            "implementation_revision": self.state.implementation_revision,
            "tasks": {task_id: asdict(task) for task_id, task in self.state.tasks.items()},
            "evidence": self.state.evidence,
            "review_cycles": self.state.review_cycles,
            "accepted_risks": self.state.accepted_risks,
            "waivers": self.state.waivers,
            "commits": self.state.commits,
        }


def mermaid() -> str:
    lines = ["flowchart TD"]
    for node_id, node in NODES.items():
        safe = node_id.replace("-", "_"); label = f"{node_id} {node.action}" if node_id.startswith(("T", "L")) else node.action
        lines.append(f'    {safe}["{label}"]')
    for edge in EDGES:
        lines.append(f"    {edge.source.replace('-', '_')} -->|{edge.outcome}| {edge.target.replace('-', '_')}")
    lines += ["    classDef human fill:#fff3cd,stroke:#9a6700", "    class T5,human_gate,human_waiver human",
              "    classDef escalation fill:#f3e8ff,stroke:#7e22ce", "    class astra_plan,astra_adjudication escalation"]
    return "\n".join(lines) + "\n"


if __name__ == "__main__": print(mermaid(), end="")
