"""Core C5 - Resource Sensitivity Classification.

Classifies resources into LOW, MEDIUM, HIGH and CRITICAL using deterministic
patterns. Unknown resources default to MEDIUM so the system fails safe rather
than treating an unrecognised resource as harmless.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Dict, List, Tuple

from .models import ActionRequest, SENSITIVITY

SENSITIVITY_SCORE: Dict[str, float] = {
    "LOW": 0.1,
    "MEDIUM": 0.4,
    "HIGH": 0.7,
    "CRITICAL": 1.0,
}

# Ordered from most to least sensitive; the first match wins.
_PATTERNS: List[Tuple[str, Tuple[str, ...]]] = [
    (
        "CRITICAL",
        (
            ".env", "*.env", "credentials*", "ssh/*", "ssh", "id_rsa",
            "secrets/*", "secret*", "*.pem", "*.key", "password*",
            ".aws/*", "token*", "private*", "vault/*",
        ),
    ),
    (
        "HIGH",
        (
            "config/*", "*.config", "settings.*", ".github/*", "infra/*",
            "deploy/*", "docker-compose*", "terraform/*", "admin/*",
            "db/*", "migrations/*",
        ),
    ),
    (
        "MEDIUM",
        (
            "src/*", "tests/*", "app/*", "api/*", "*.py", "*.js", "*.ts",
            "package.json", "requirements.txt", "go.mod", "pom.xml",
        ),
    ),
    (
        "LOW",
        ("docs/*", "README*", "*.md", "examples/*", "data/public/*", "LICENSE*"),
    ),
]


@dataclass(frozen=True)
class Classification:
    label: str
    score: float
    matched_pattern: str

    def to_dict(self) -> Dict[str, object]:
        return {"label": self.label, "score": self.score, "pattern": self.matched_pattern}


class ResourceClassifier:
    """Assign a deterministic sensitivity level to a resource path or URL."""

    def classify(self, resource: str) -> Classification:
        value = (resource or "").strip().lstrip("./")
        for label, patterns in _PATTERNS:
            for pattern in patterns:
                if fnmatch.fnmatch(value, pattern) or fnmatch.fnmatch(resource, pattern):
                    return Classification(label, SENSITIVITY_SCORE[label], pattern)
        return Classification("MEDIUM", SENSITIVITY_SCORE["MEDIUM"], "default")

    def classify_action(self, action: ActionRequest) -> Classification:
        return self.classify(action.resource)

    @staticmethod
    def valid(label: str) -> bool:
        return label in SENSITIVITY
