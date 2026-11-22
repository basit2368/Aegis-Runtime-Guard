"""Core C1 - Agent Gateway.

The gateway is the single interception point through which every protected
agent tool call passes before it can reach an external tool (FR-012, FR-013).
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

from .audit import AuditLogger
from .capability import CapabilityManager
from .config import Config
from .decision import DecisionEngine
from .executor import ControlledExecutor
from .intent import IntentAnalyzer, LLMIntentClient
from .models import ActionRequest, Capability, Decision, Task, new_id
from .policy import PolicyEngine
from .resources import ResourceClassifier
from .risk import RiskEngine


class AegisGateway:
    """Register tasks and authorize/execute agent actions."""

    def __init__(
        self,
        config: Optional[Config] = None,
        audit: Optional[AuditLogger] = None,
        llm_client: Optional[LLMIntentClient] = None,
    ) -> None:
        self.config = config or Config()
        self.audit = audit or AuditLogger(config=self.config)
        self.intent_analyzer = IntentAnalyzer(llm_client)
        self.capabilities = CapabilityManager(self.config)
        self.classifier = ResourceClassifier()
        self.policy = PolicyEngine(self.capabilities, self.classifier)
        self.risk = RiskEngine(self.config)
        self.decision_engine = DecisionEngine(self.risk, self.config)
        self.executor = ControlledExecutor(self.config)
        self.tasks: Dict[str, Task] = {}
        self._task_capability: Dict[str, Capability] = {}

    def register_task(self, description: str, owner: str = "operator") -> Task:
        """Create a task, analyze its intent and issue a scoped capability."""
        task = Task(id=new_id("TASK"), description=description, owner=owner)
        intent = self.intent_analyzer.analyze(task)
        task.intent = intent
        task.status = "ACTIVE"
        capability = self.capabilities.issue(task, intent)
        self.tasks[task.id] = task
        self._task_capability[task.id] = capability
        self.audit.log_task(task)
        self.audit.log_capability(task.id, capability.to_dict())
        return task

    def get_task(self, task_id: str) -> Task:
        try:
            return self.tasks[task_id]
        except KeyError as exc:
            raise KeyError(f"Unknown task: {task_id}") from exc

    def capability_for(self, task_id: str) -> Capability:
        return self._task_capability[task_id]

    def revoke_capability(self, task_id: str) -> bool:
        """Revoke a task's capability; the next action is denied."""
        cap = self._task_capability.get(task_id)
        if not cap:
            return False
        revoked = self.capabilities.revoke(cap.token)
        if revoked:
            self.audit.log(
                "CAPABILITY_REVOKED", {"task_id": task_id, "token_prefix": cap.token[:12]}, task_id
            )
        return revoked

    def authorize(self, task_id: str, action: ActionRequest) -> Decision:
        """Authorize one action without executing it."""
        started = time.perf_counter()
        task = self.get_task(task_id)
        if task.intent is None:
            raise RuntimeError(f"Task {task_id} has no intent profile")

        cap = self._task_capability.get(task_id)
        capability, reason = (
            self.capabilities.validate(cap.token)
            if cap is not None
            else (None, "No capability was issued for this task")
        )
        classification = self.classifier.classify_action(action)
        policy = self.policy.evaluate(action, task.intent, capability, classification)
        risk = self.risk.evaluate(action, task.intent, classification)
        latency = (time.perf_counter() - started) * 1000
        decision = self.decision_engine.decide(
            action, task.intent, capability, reason, policy, risk, latency_ms=latency
        )
        self.audit.log_decision(decision)
        return decision

    def execute(self, task_id: str, action: ActionRequest) -> Decision:
        """Authorize and, only if allowed, execute the action."""
        decision = self.authorize(task_id, action)
        if decision.outcome == "ALLOW":
            result = self.executor.execute(action)
            decision.executed = True
            decision.execution_result = result
            self.audit.log_execution(decision, result)
        return decision

    def handle(
        self,
        task_id: str,
        tool: str,
        operation: str,
        resource: str,
        params: Optional[Dict[str, Any]] = None,
        source: str = "agent",
        execute: bool = True,
    ) -> Decision:
        """Convenience wrapper used by the CLI, dashboard and evaluation harness."""
        action = ActionRequest(
            task_id=task_id,
            tool=tool,
            operation=operation,
            resource=resource,
            params=params or {},
            source=source,
        )
        return self.execute(task_id, action) if execute else self.authorize(task_id, action)
