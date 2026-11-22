"""Central configuration for the AEGIS FYP-I prototype.

All values can be overridden with environment variables so the same code can be
used for development, evaluation and demonstration without editing source files.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "aegis.db"
RESULTS_PATH = DATA_DIR / "evaluation_results.json"


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Config:
    """Runtime configuration."""

    secret_key: str = field(
        default_factory=lambda: os.getenv("AEGIS_SECRET", "aegis-fyp1-demo-secret")
    )
    capability_ttl_minutes: int = field(
        default_factory=lambda: _int_env("AEGIS_CAPABILITY_TTL", 30)
    )
    # Initial weights; tuned on the validation split by RiskEngine.tune().
    weight_intent: float = field(default_factory=lambda: _float_env("AEGIS_W_INTENT", 0.5))
    weight_sensitivity: float = field(default_factory=lambda: _float_env("AEGIS_W_SENS", 0.3))
    weight_privilege: float = field(default_factory=lambda: _float_env("AEGIS_W_PRIV", 0.2))
    theta_allow: float = field(default_factory=lambda: _float_env("AEGIS_THETA_ALLOW", 0.35))
    theta_deny: float = field(default_factory=lambda: _float_env("AEGIS_THETA_DENY", 0.65))
    # FYP-I is allow/deny only; the escalation band fails closed.
    escalation_policy: str = field(
        default_factory=lambda: os.getenv("AEGIS_ESCALATION", "deny")
    )
    simulated_execution_ms: int = field(
        default_factory=lambda: _int_env("AEGIS_EXECUTION_MS", 5)
    )
    db_path: Path = field(default_factory=lambda: Path(os.getenv("AEGIS_DB", str(DB_PATH))))
    results_path: Path = field(
        default_factory=lambda: Path(os.getenv("AEGIS_RESULTS", str(RESULTS_PATH)))
    )
    random_seed: int = field(default_factory=lambda: _int_env("AEGIS_SEED", 42))

    def with_weights(self, w_i: float, w_s: float, w_p: float, allow: float, deny: float) -> "Config":
        """Return a copy with tuned risk parameters."""
        return replace(
            self,
            weight_intent=w_i,
            weight_sensitivity=w_s,
            weight_privilege=w_p,
            theta_allow=allow,
            theta_deny=deny,
        )


CONFIG = Config()
