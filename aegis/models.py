"""Core data model for AEGIS.

The model intentionally keeps security state explicit and serialisable so that
every decision can be reconstructed from the audit log during evaluation.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set

OPERATIONS = ("READ", "WRITE", "EXECUTE", "NETWORK", "DELETE", "DATABASE")
SENSITIVITY = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def new_id(prefix: str) -> str:
    """Return a short, unique, human-readable identifier."""
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


def now_ts() -> float:
    return time.time()


@dataclass
class IntentProfile:
    """Structured security context extracted from a natural-language task."""

    objective: str
    expected_operations: Set[str] = field(default_factory=set)
    expected_resources: List[str] = field(default_factory=list)
    prohibited_operations: Set[str] = field(default_factory=set)
    prohibited_resources: List[str] = field(default_factory=list)
    network_policy: str = "restricted"  # restricted | denied | allowed
    confidence: float = 0.7
    source: str = "deterministic"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["expected_operations"] = sorted(self.expected_operations)
        data["prohibited_operations"] = sorted(self.prohibited_operations)
        return data


@dataclass
class Task:
    """A user-submitted goal and its lifecycle."""

    id: str
    description: str
    owner: str = "operator"
    status: str = "REGISTERED"
    created_at: float = field(default_factory=now_ts)
    intent: Optional[IntentProfile] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "owner": self.owner,
            "status": self.status,
            "created_at": self.created_at,
            "intent": self.intent.to_dict() if self.intent else None,
        }


@dataclass
class Capability:
    """A signed, task-scoped, time-limited authorization grant."""

    token: str
    task_id: str
    allowed_operations: Set[str]
    allowed_resources: List[str]
    denied_resources: List[str]
    network_policy: str
    issued_at: float
    expires_at: float
    status: str = "ACTIVE"
    signature: str = ""

    def is_expired(self, at: Optional[float] = None) -> bool:
        return (at or now_ts()) >= self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "allowed_operations": sorted(self.allowed_operations),
            "allowed_resources": self.allowed_resources,
            "denied_resources": self.denied_resources,
            "network_policy": self.network_policy,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "status": self.status,
        }


@dataclass
class ActionRequest:
    """A normalized agent tool call intercepted by the gateway."""

    task_id: str
    tool: str
    operation: str
    resource: str
    params: Dict[str, Any] = field(default_factory=dict)
    source: str = "agent"  # agent | untrusted_content
    id: str = field(default_factory=lambda: new_id("ACT"))
    timestamp: float = field(default_factory=now_ts)

    def __post_init__(self) -> None:
        self.operation = self.operation.upper()
        if self.operation not in OPERATIONS:
            raise ValueError(f"Unsupported operation: {self.operation}")
        # FR-013: normalize a terminal command to its executable so scope checks
        # apply to the tool being invoked, while the full command stays in params.
        if self.operation == "EXECUTE" and " " in self.resource:
            full_command = self.resource
            self.params.setdefault("command", full_command)
            self.resource = full_command.split()[0]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PolicyResult:
    """Outcome of deterministic policy evaluation."""

    effect: str  # ALLOW | DENY
    rule_id: str
    reason: str
    trace: List[str] = field(default_factory=list)

    @property
    def denied(self) -> bool:
        return self.effect == "DENY"


@dataclass
class RiskResult:
    """Contextual risk factors and score."""

    intent_deviation: float
    sensitivity: float
    privilege: float
    score: float
    outcome: str  # ALLOW | DENY | ESCALATE
    sensitivity_label: str
    weights: Dict[str, float] = field(default_factory=dict)
    thresholds: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Decision:
    """Final runtime authorization decision with a human-readable explanation."""

    action_id: str
    task_id: str
    outcome: str  # ALLOW | DENY
    reason: str
    explanation: str
    policy: PolicyResult
    risk: Optional[RiskResult] = None
    capability_id: str = ""
    latency_ms: float = 0.0
    executed: bool = False
    execution_result: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "task_id": self.task_id,
            "outcome": self.outcome,
            "reason": self.reason,
            "explanation": self.explanation,
            "policy": {
                "effect": self.policy.effect,
                "rule_id": self.policy.rule_id,
                "reason": self.policy.reason,
                "trace": self.policy.trace,
            },
            "risk": self.risk.to_dict() if self.risk else None,
            "capability_id": self.capability_id,
            "latency_ms": round(self.latency_ms, 3),
            "executed": self.executed,
            "execution_result": self.execution_result,
        }


@dataclass
class ScenarioAction:
    """One labelled action inside an evaluation scenario."""

    tool: str
    operation: str
    resource: str
    params: Dict[str, Any] = field(default_factory=dict)
    source: str = "agent"
    expected: str = "ALLOW"  # ALLOW | DENY

    def to_action(self, task_id: str) -> ActionRequest:
        return ActionRequest(
            task_id=task_id,
            tool=self.tool,
            operation=self.operation,
            resource=self.resource,
            params=dict(self.params),
            source=self.source,
        )


@dataclass
class Scenario:
    """A controlled legitimate or adversarial task used in evaluation."""

    id: str
    description: str
    category: str  # legitimate | adversarial
    attack_type: str
    actions: List[ScenarioAction]
    split: str = "test"  # validation | test


def decision_json(decision: Decision) -> str:
    """Canonical JSON for audit and reproducibility."""
    return json.dumps(decision.to_dict(), sort_keys=True, separators=(",", ":"))
