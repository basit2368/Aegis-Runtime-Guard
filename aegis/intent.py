"""Core C2 - Intent Analyzer.

The FYP-I analyzer is deterministic so the prototype works without network
access and every extraction can be reproduced. An optional LLM adapter can be
injected; if it fails or returns an invalid profile the deterministic analyzer
is used as a safe fallback (FR-004, FR-005, FR-006).
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple

from .models import IntentProfile, Task


class LLMIntentClient(Protocol):
    """Optional external intent analyzer interface.

    Implementations must expose ``analyze(description: str) -> str`` returning
    a JSON object with the same keys as :class:`IntentProfile`.
    """

    def analyze(self, description: str) -> str: ...


# (keywords, operations, resources, prohibited operations, prohibited resources)
_RULES: List[Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]] = [
    (
        ("fix", "repair", "bug", "patch", "debug"),
        ("READ", "WRITE", "EXECUTE"),
        ("src/*", "tests/*", "package.json", "requirements.txt"),
        ("DELETE",),
        (),
    ),
    (
        ("test", "pytest", "unittest", "run tests", "verify"),
        ("READ", "EXECUTE"),
        ("tests/*", "src/*"),
        ("DELETE", "NETWORK"),
        (),
    ),
    (
        ("document", "docs", "readme", "explain", "write docs"),
        ("READ", "WRITE"),
        ("docs/*", "README*", "src/*"),
        ("DELETE", "NETWORK"),
        (),
    ),
    (
        ("refactor", "improve", "clean up", "restructure"),
        ("READ", "WRITE", "EXECUTE"),
        ("src/*", "tests/*"),
        ("DELETE", "NETWORK"),
        (),
    ),
    (
        ("database", "query", "sql", "schema", "migration"),
        ("READ", "WRITE", "DATABASE"),
        ("src/*", "db/*", "migrations/*"),
        ("DELETE", "NETWORK"),
        (),
    ),
    (
        ("api", "endpoint", "fetch", "call api", "integrate"),
        ("READ", "WRITE", "NETWORK"),
        ("src/*", "tests/*", "api/*"),
        ("DELETE",),
        (),
    ),
    (
        ("delete", "remove", "drop table", "wipe"),
        ("DELETE",),
        ("src/*", "tests/*"),
        (),
        (),
    ),
]

_SECRET_PATTERNS: Tuple[str, ...] = (
    ".env",
    "*.env",
    "credentials*",
    "ssh/*",
    "id_rsa",
    "secrets/*",
    "*.pem",
    "*.key",
    "password*",
    ".aws/*",
    "token*",
)

_NETWORK_DENIED_KEYWORDS: Tuple[str, ...] = ("secret", "credential", "password", "private")


class IntentAnalyzer:
    """Extract a structured security context from a natural-language task."""

    def __init__(self, llm_client: Optional[LLMIntentClient] = None) -> None:
        self.llm_client = llm_client

    def analyze(self, task: Task) -> IntentProfile:
        """Analyze ``task`` and return a validated intent profile."""
        if self.llm_client is not None:
            try:
                raw = self.llm_client.analyze(task.description)
                profile = self._from_llm_json(raw, task.description)
                if profile is not None:
                    return profile
            except Exception:  # pragma: no cover - depends on external service
                pass
        return self.analyze_deterministic(task.description)

    def analyze_deterministic(self, description: str) -> IntentProfile:
        """Rule-based extraction used for FYP-I and as the LLM fallback."""
        text = description.lower()
        operations: set[str] = set()
        resources: List[str] = []
        prohibited_ops: set[str] = set()
        prohibited_resources: List[str] = []

        for keywords, ops, res, bad_ops, bad_res in _RULES:
            if any(re.search(r"\b" + re.escape(k) + r"\b", text) for k in keywords):
                operations.update(ops)
                resources.extend(r for r in res if r not in resources)
                prohibited_ops.update(bad_ops)
                prohibited_resources.extend(r for r in bad_res if r not in prohibited_resources)

        if not operations:
            operations = {"READ"}
            resources = ["docs/*", "src/*"]
            prohibited_ops = {"DELETE", "NETWORK"}
            confidence = 0.55
        else:
            confidence = min(0.95, 0.65 + 0.05 * len(operations))

        # General documentation is a safe, low-sensitivity context for every task.
        for safe_pattern in ("docs/*", "README*"):
            if safe_pattern not in resources:
                resources.append(safe_pattern)

        if "EXECUTE" in operations:
            for executable in ("pytest", "python*"):
                if executable not in resources:
                    resources.append(executable)

        prohibited_resources.extend(
            p for p in _SECRET_PATTERNS if p not in prohibited_resources
        )
        # Secrets are always outside the intended task unless explicitly named.
        if any(word in text for word in ("secret", "credential", "ssh key", ".env")):
            confidence = min(confidence, 0.6)

        network_policy = "restricted"
        if "network" in operations or "api" in text:
            network_policy = "restricted"
        if any(word in text for word in _NETWORK_DENIED_KEYWORDS):
            network_policy = "denied"

        return IntentProfile(
            objective=description.strip(),
            expected_operations=operations,
            expected_resources=resources or ["docs/*", "src/*"],
            prohibited_operations=prohibited_ops,
            prohibited_resources=prohibited_resources,
            network_policy=network_policy,
            confidence=round(confidence, 2),
            source="deterministic",
        )

    @staticmethod
    def _from_llm_json(raw: str, fallback_objective: str) -> Optional[IntentProfile]:
        """Validate and normalise an optional LLM-produced intent profile."""
        data: Dict[str, Any] = json.loads(raw)
        if not isinstance(data, dict) or "expected_operations" not in data:
            return None
        ops = {str(o).upper() for o in data.get("expected_operations", [])}
        if not ops:
            return None
        bad_ops = {str(o).upper() for o in data.get("prohibited_operations", [])}
        resources = [str(r) for r in data.get("expected_resources", [])]
        return IntentProfile(
            objective=str(data.get("objective", fallback_objective)),
            expected_operations=ops,
            expected_resources=resources or ["docs/*", "src/*"],
            prohibited_operations=bad_ops or {"DELETE"},
            prohibited_resources=[str(r) for r in data.get("prohibited_resources", [])]
            or list(_SECRET_PATTERNS),
            network_policy=str(data.get("network_policy", "restricted")),
            confidence=float(data.get("confidence", 0.7)),
            source="llm",
        )
