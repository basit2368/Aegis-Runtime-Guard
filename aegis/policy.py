"""Core C4 - Policy Engine.

Deterministic rules are evaluated in order and a DENY from any rule is a hard
deny: it cannot be overridden by a contextual risk score (FR-017, BR-01).
The complete trace is returned for the audit record and explanation.
"""

from __future__ import annotations

import fnmatch
from typing import Iterable, List, Optional

from .capability import CapabilityManager
from .models import ActionRequest, Capability, IntentProfile, PolicyResult
from .resources import Classification, ResourceClassifier


class PolicyEngine:
    """Evaluate deterministic security rules for one action."""

    def __init__(self, capability_manager: CapabilityManager, classifier: Optional[ResourceClassifier] = None) -> None:
        self.caps = capability_manager
        self.classifier = classifier or ResourceClassifier()

    def evaluate(
        self,
        action: ActionRequest,
        intent: IntentProfile,
        capability: Optional[Capability],
        classification: Optional[Classification] = None,
    ) -> PolicyResult:
        trace: List[str] = []
        classification = classification or self.classifier.classify_action(action)
        trace.append(f"P000 resource classified as {classification.label}")

        if capability is None:
            return self._deny("P001", "No valid capability for this action", trace)

        if action.operation == "DELETE" and action.operation not in intent.expected_operations:
            return self._deny("P002", "Deletion is not part of the registered task intent", trace)

        if action.operation in intent.prohibited_operations:
            return self._deny("P003", f"Operation {action.operation} is prohibited for this task", trace)

        if classification.label == "CRITICAL" and not CapabilityManager.explicitly_allows(
            capability, action.resource
        ):
            return self._deny(
                "P004",
                f"CRITICAL resource '{action.resource}' is not explicitly named in the capability",
                trace,
            )

        if any(
            fnmatch.fnmatch(action.resource, pattern)
            for pattern in capability.denied_resources
        ):
            return self._deny("P005", "Resource is explicitly denied by the capability", trace)

        if action.operation not in capability.allowed_operations:
            return self._deny(
                "P006",
                f"Operation {action.operation} is outside the capability scope",
                trace,
            )

        if action.operation == "NETWORK" and not CapabilityManager.network_allowed(
            capability, action.resource
        ):
            return self._deny("P007", "Network destination is not allowed by the capability", trace)

        if not CapabilityManager.resource_allowed(capability, action.resource):
            return self._deny(
                "P008", f"Resource '{action.resource}' is outside the capability scope", trace
            )

        if action.source == "untrusted_content" and action.operation in {
            "NETWORK", "DELETE", "EXECUTE"
        }:
            return self._deny(
                "P009",
                "Action originated from untrusted content and has an external effect",
                trace,
            )

        trace.append("P010 all deterministic rules satisfied")
        return PolicyResult("ALLOW", "P010", "Action satisfies all deterministic rules", trace)

    @staticmethod
    def _deny(rule_id: str, reason: str, trace: Iterable[str]) -> PolicyResult:
        items = list(trace)
        items.append(f"{rule_id} DENY - {reason}")
        return PolicyResult("DENY", rule_id, reason, items)
