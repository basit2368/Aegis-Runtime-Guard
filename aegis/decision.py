"""Core C7 - Allow/Deny Decision Engine.

Combines deterministic policy, capability validity and contextual risk. Policy
denials are hard denials; FYP-I has no human-approval extension, so the risk
escalation band fails closed by configuration.
"""

from __future__ import annotations

from typing import Dict, Optional

from .config import Config
from .models import ActionRequest, Capability, Decision, IntentProfile, PolicyResult, RiskResult
from .risk import RiskEngine


class DecisionEngine:
    """Produce the final runtime authorization decision and explanation."""

    def __init__(self, risk_engine: RiskEngine, config: Optional[Config] = None) -> None:
        self.risk = risk_engine
        self.config = config or Config()

    def decide(
        self,
        action: ActionRequest,
        intent: IntentProfile,
        capability: Optional[Capability],
        capability_reason: str,
        policy: PolicyResult,
        risk: RiskResult,
        latency_ms: float = 0.0,
    ) -> Decision:
        outcome = "ALLOW"
        reason = "Action satisfies capability, policy and risk checks"

        if capability is None:
            outcome, reason = "DENY", f"Capability invalid: {capability_reason}"
        elif policy.denied:
            outcome, reason = "DENY", f"Hard policy denial [{policy.rule_id}]: {policy.reason}"
        elif risk.outcome == "DENY":
            outcome, reason = "DENY", f"Risk score {risk.score} exceeds the deny threshold"
        elif risk.outcome == "ESCALATE":
            if self.config.escalation_policy == "deny":
                outcome = "DENY"
                reason = (
                    f"Risk score {risk.score} is in the escalation band; "
                    "FYP-I fails closed (no approval extension)"
                )
            else:
                outcome = "ALLOW"
                reason = f"Risk score {risk.score} is in the escalation band; configured to allow"

        explanation = self.explain(action, capability, policy, risk, outcome, reason)
        return Decision(
            action_id=action.id,
            task_id=action.task_id,
            outcome=outcome,
            reason=reason,
            explanation=explanation,
            policy=policy,
            risk=risk,
            capability_id=capability.token.split(".")[0][:12] if capability else "",
            latency_ms=latency_ms,
        )

    @staticmethod
    def explain(
        action: ActionRequest,
        capability: Optional[Capability],
        policy: PolicyResult,
        risk: RiskResult,
        outcome: str,
        reason: str,
    ) -> str:
        parts = [
            f"{action.operation} on '{action.resource}' -> {outcome}.",
            f"Reason: {reason}.",
            f"Policy rule: {policy.rule_id} ({policy.effect}).",
            f"Risk: I={risk.intent_deviation}, S={risk.sensitivity} ({risk.sensitivity_label}), "
            f"P={risk.privilege}, R={risk.score}.",
            f"Capability: {'present' if capability else 'absent'}.",
        ]
        return " ".join(parts)

    def summary(self, decisions) -> Dict[str, int]:
        counts = {"ALLOW": 0, "DENY": 0}
        for decision in decisions:
            counts[decision.outcome] = counts.get(decision.outcome, 0) + 1
        return counts
