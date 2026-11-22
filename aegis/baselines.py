"""Core C9 - Baseline systems.

Two baselines reproduce conventional approaches for comparison:

* ``UnprotectedAgent`` executes every action with no authorization checks.
* ``StaticPermissionAgent`` applies fixed role-level permissions but has no
  knowledge of the registered task intent or dynamic capabilities.

Both expose the same ``decide`` interface as the AEGIS gateway for evaluation.
"""

from __future__ import annotations

import fnmatch
import time
from typing import Optional

from .config import Config
from .models import (
    ActionRequest,
    Decision,
    IntentProfile,
    PolicyResult,
    RiskResult,
    ScenarioAction,
)
from .resources import ResourceClassifier


def _baseline_decision(
    action: ActionRequest,
    outcome: str,
    rule_id: str,
    reason: str,
    latency_ms: float,
) -> Decision:
    policy = PolicyResult(outcome, rule_id, reason, [f"{rule_id}: {reason}"])
    risk = RiskResult(
        intent_deviation=0.0,
        sensitivity=0.0,
        privilege=0.0,
        score=0.0,
        outcome=outcome,
        sensitivity_label="N/A",
    )
    return Decision(
        action_id=action.id,
        task_id=action.task_id,
        outcome=outcome,
        reason=reason,
        explanation=f"Baseline decision: {reason}",
        policy=policy,
        risk=risk,
        capability_id="baseline",
        latency_ms=latency_ms,
    )


class UnprotectedAgent:
    """Baseline A: no authorization layer; every action is allowed."""

    name = "Unprotected"

    def register_task(self, description: str) -> IntentProfile:
        return IntentProfile(objective=description)

    def decide(self, task_id: str, scenario_action: ScenarioAction) -> Decision:
        action = scenario_action.to_action(task_id)
        time.sleep(0)  # baseline has no decision cost
        return _baseline_decision(
            action, "ALLOW", "B-A-001", "Unprotected agent allows every action", 0.0
        )


class StaticPermissionAgent:
    """Baseline B: static permissions, no task intent or capabilities."""

    name = "StaticPermission"

    ALLOWED_PATTERNS = (
        "src/*", "tests/*", "docs/*", "README*", "requirements.txt", "pytest", "python*"
    )
    ALLOWED_OPS = {"READ", "WRITE", "EXECUTE", "DATABASE"}

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config()
        self.classifier = ResourceClassifier()

    def register_task(self, description: str) -> IntentProfile:
        return IntentProfile(objective=description)

    def decide(self, task_id: str, scenario_action: ScenarioAction) -> Decision:
        action = scenario_action.to_action(task_id)
        started = time.perf_counter()
        classification = self.classifier.classify_action(action)

        if classification.label == "CRITICAL":
            outcome, rule, reason = "DENY", "B-B-001", "Static policy denies CRITICAL resources"
        elif action.operation == "DELETE":
            outcome, rule, reason = "DENY", "B-B-002", "Static policy denies DELETE"
        elif action.operation == "NETWORK":
            outcome, rule, reason = "DENY", "B-B-003", "Static policy denies NETWORK"
        elif action.operation not in self.ALLOWED_OPS:
            outcome, rule, reason = "DENY", "B-B-004", "Operation is not in the static allow-list"
        elif not any(fnmatch.fnmatch(action.resource, p) for p in self.ALLOWED_PATTERNS):
            outcome, rule, reason = "DENY", "B-B-005", "Resource is outside the static allow-list"
        else:
            outcome, rule, reason = "ALLOW", "B-B-006", "Action matches static role permissions"

        latency = (time.perf_counter() - started) * 1000
        return _baseline_decision(action, outcome, rule, reason, latency)
