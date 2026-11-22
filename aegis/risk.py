"""Core C6 - Contextual Risk Engine.

Risk is R = wI*I + wS*S + wP*P where:
  I = intent deviation in [0, 1]
  S = resource sensitivity in {0.1, 0.4, 0.7, 1.0}
  P = privilege required by the operation in [0, 1]

Weights and thresholds are tuned on a validation split and then frozen before
the held-out test split is evaluated (as committed in the proposal).
"""

from __future__ import annotations

import fnmatch
import itertools
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .config import Config
from .models import ActionRequest, IntentProfile, RiskResult
from .resources import Classification, ResourceClassifier, SENSITIVITY_SCORE

PRIVILEGE_SCORE: Dict[str, float] = {
    "READ": 0.1,
    "WRITE": 0.4,
    "DATABASE": 0.5,
    "EXECUTE": 0.7,
    "NETWORK": 0.8,
    "DELETE": 1.0,
}


@dataclass(frozen=True)
class RiskFactors:
    """Raw factors used for tuning and evaluation."""

    intent_deviation: float
    sensitivity: float
    privilege: float
    sensitivity_label: str

    @property
    def as_tuple(self) -> Tuple[float, float, float]:
        return (self.intent_deviation, self.sensitivity, self.privilege)


class RiskEngine:
    """Compute and tune the contextual risk score."""

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config()
        self.classifier = ResourceClassifier()

    def factors(
        self,
        action: ActionRequest,
        intent: IntentProfile,
        classification: Optional[Classification] = None,
    ) -> RiskFactors:
        """Compute I, S and P for one action."""
        classification = classification or self.classifier.classify_action(action)

        if (
            action.source == "untrusted_content"
            or action.operation in intent.prohibited_operations
            or any(
                fnmatch.fnmatch(action.resource, pattern)
                for pattern in intent.prohibited_resources
            )
        ):
            deviation = 1.0
        elif action.operation not in intent.expected_operations:
            deviation = 0.7
        elif not any(
            fnmatch.fnmatch(action.resource, pattern)
            for pattern in intent.expected_resources
        ):
            deviation = 0.4
        else:
            deviation = 0.0

        return RiskFactors(
            intent_deviation=round(deviation, 3),
            sensitivity=classification.score,
            privilege=PRIVILEGE_SCORE.get(action.operation, 0.5),
            sensitivity_label=classification.label,
        )

    def score(self, factors: RiskFactors) -> float:
        i, s, p = factors.as_tuple
        raw = (
            self.config.weight_intent * i
            + self.config.weight_sensitivity * s
            + self.config.weight_privilege * p
        )
        return round(min(1.0, max(0.0, raw)), 4)

    def outcome(self, score: float) -> str:
        if score < self.config.theta_allow:
            return "ALLOW"
        if score > self.config.theta_deny:
            return "DENY"
        return "ESCALATE"

    def evaluate(
        self,
        action: ActionRequest,
        intent: IntentProfile,
        classification: Optional[Classification] = None,
    ) -> RiskResult:
        factors = self.factors(action, intent, classification)
        score = self.score(factors)
        return RiskResult(
            intent_deviation=factors.intent_deviation,
            sensitivity=factors.sensitivity,
            privilege=factors.privilege,
            score=score,
            outcome=self.outcome(score),
            sensitivity_label=factors.sensitivity_label,
            weights={
                "I": self.config.weight_intent,
                "S": self.config.weight_sensitivity,
                "P": self.config.weight_privilege,
            },
            thresholds={
                "allow": self.config.theta_allow,
                "deny": self.config.theta_deny,
            },
        )

    def tune(
        self,
        samples: Sequence[Tuple[RiskFactors, str]],
        max_fpr: float = 0.20,
    ) -> Dict[str, object]:
        """Grid-search weights and thresholds on labelled validation data.

        Returns the best parameters and the validation metrics. DENY is the
        positive class; FPR is the fraction of legitimate actions denied.
        """
        if not samples:
            raise ValueError("No validation samples provided")

        best: Dict[str, object] | None = None
        # Weight grid: integer tenths that sum to exactly 1.0.
        for hundredths in itertools.product(range(0, 11), repeat=2):
            wi, ws = hundredths
            wp = 10 - wi - ws
            if wp < 0:
                continue
            w_i, w_s, w_p = wi / 10, ws / 10, wp / 10
            scores = [
                (w_i * f.intent_deviation + w_s * f.sensitivity + w_p * f.privilege, label)
                for f, label in samples
            ]
            for allow in [round(0.05 * k, 2) for k in range(1, 18)]:
                for deny in [round(0.05 * k, 2) for k in range(1, 19)]:
                    if deny <= allow:
                        continue
                    tp = fp = tn = fn = 0
                    for value, label in scores:
                        predicted = "DENY" if value >= deny else (
                            "ALLOW" if value <= allow else "DENY"  # FYP-I fail-closed band
                        )
                        if predicted == "DENY" and label == "DENY":
                            tp += 1
                        elif predicted == "DENY" and label == "ALLOW":
                            fp += 1
                        elif predicted == "ALLOW" and label == "ALLOW":
                            tn += 1
                        else:
                            fn += 1
                    precision = tp / (tp + fp) if tp + fp else 1.0
                    recall = tp / (tp + fn) if tp + fn else 0.0
                    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
                    fpr = fp / (fp + tn) if fp + tn else 0.0
                    objective = f1 - 2.0 * max(0.0, fpr - max_fpr)
                    candidate: Dict[str, object] = {
                        "weight_intent": w_i,
                        "weight_sensitivity": w_s,
                        "weight_privilege": w_p,
                        "theta_allow": allow,
                        "theta_deny": deny,
                        "validation_f1": round(f1, 4),
                        "validation_fpr": round(fpr, 4),
                        "validation_precision": round(precision, 4),
                        "validation_recall": round(recall, 4),
                        "objective": round(objective, 4),
                    }
                    if best is None or objective > float(best["objective"]):
                        best = candidate

        assert best is not None
        return best

    def apply_tuning(self, params: Dict[str, object]) -> Config:
        """Return a frozen configuration using tuned parameters."""
        return self.config.with_weights(
            float(params["weight_intent"]),
            float(params["weight_sensitivity"]),
            float(params["weight_privilege"]),
            float(params["theta_allow"]),
            float(params["theta_deny"]),
        )
