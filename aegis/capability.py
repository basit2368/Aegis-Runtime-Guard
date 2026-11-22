"""Core C3 - Capability Manager.

Capabilities are task-scoped, least-privilege, time-limited and revocable.
They are HMAC-signed JSON tokens; no external JWT library is required, which
keeps the FYP-I prototype self-contained and reproducible.
"""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import hmac
import json
import uuid
from typing import Any, Dict, Optional, Tuple

from .config import Config
from .models import Capability, IntentProfile, Task, now_ts


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


class CapabilityManager:
    """Issue, validate and revoke signed capability tokens."""

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config()
        self._revoked: set[str] = set()
        self._issued: Dict[str, Capability] = {}

    def issue(self, task: Task, intent: IntentProfile) -> Capability:
        """Create a capability derived from the analyzed intent."""
        issued = now_ts()
        expires = issued + self.config.capability_ttl_minutes * 60
        allowed_ops = sorted(intent.expected_operations - intent.prohibited_operations)
        payload: Dict[str, Any] = {
            "task_id": task.id,
            "allowed_operations": allowed_ops,
            "allowed_resources": list(intent.expected_resources),
            "denied_resources": list(intent.prohibited_resources),
            "network_policy": intent.network_policy,
            "issued_at": round(issued, 6),
            "expires_at": round(expires, 6),
            "status": "ACTIVE",
            "nonce": uuid.uuid4().hex[:12],
        }
        body = _b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        signature = self._sign(body)
        token = f"{body}.{signature}"
        cap = Capability(
            token=token,
            task_id=task.id,
            allowed_operations=set(allowed_ops),
            allowed_resources=list(intent.expected_resources),
            denied_resources=list(intent.prohibited_resources),
            network_policy=intent.network_policy,
            issued_at=issued,
            expires_at=expires,
            signature=signature,
        )
        self._issued[token] = cap
        return cap

    def validate(self, token: str, task_id: Optional[str] = None) -> Tuple[Optional[Capability], str]:
        """Return ``(capability, reason)``; capability is ``None`` when invalid.

        When ``task_id`` is supplied the token must belong to that exact task,
        which prevents a valid capability from being replayed across tasks.
        """
        if not token or "." not in token:
            return None, "Malformed capability token"
        body, supplied_sig = token.rsplit(".", 1)
        expected_sig = self._sign(body)
        if not hmac.compare_digest(supplied_sig, expected_sig):
            return None, "Capability signature is invalid"
        try:
            payload = json.loads(_b64decode(body).decode("utf-8"))
        except Exception:
            return None, "Capability payload cannot be decoded"
        if task_id is not None and str(payload.get("task_id", "")) != task_id:
            return None, "Capability does not belong to this task"
        if payload.get("status") != "ACTIVE" or body in self._revoked:
            return None, "Capability has been revoked"
        if float(payload.get("expires_at", 0)) <= now_ts():
            return None, "Capability has expired"
        cap = Capability(
            token=token,
            task_id=str(payload.get("task_id", "")),
            allowed_operations=set(payload.get("allowed_operations", [])),
            allowed_resources=list(payload.get("allowed_resources", [])),
            denied_resources=list(payload.get("denied_resources", [])),
            network_policy=str(payload.get("network_policy", "restricted")),
            issued_at=float(payload.get("issued_at", 0)),
            expires_at=float(payload.get("expires_at", 0)),
            signature=supplied_sig,
        )
        return cap, "Capability is valid"

    def revoke(self, token: str) -> bool:
        """Revoke a token immediately; revocation applies to the next action."""
        body = token.split(".", 1)[0] if token else ""
        if body not in self._revoked and body:
            self._revoked.add(body)
            if body in self._issued:
                self._issued[body].status = "REVOKED"
            return True
        return False

    @staticmethod
    def resource_allowed(cap: Capability, resource: str) -> bool:
        """Check a resource against the capability's allow/deny patterns."""
        if any(fnmatch.fnmatch(resource, pattern) for pattern in cap.denied_resources):
            return False
        return any(fnmatch.fnmatch(resource, pattern) for pattern in cap.allowed_resources)

    @staticmethod
    def explicitly_allows(cap: Capability, resource: str) -> bool:
        """True only when a critical resource is named exactly by the capability."""
        return any(
            pattern == resource and "*" not in pattern
            for pattern in cap.allowed_resources
        )

    @staticmethod
    def network_allowed(cap: Capability, resource: str) -> bool:
        """Apply the capability's network policy to a network action."""
        if cap.network_policy == "denied":
            return False
        if cap.network_policy == "allowed":
            return True
        # Restricted: only destinations explicitly listed in the capability.
        return any(
            fnmatch.fnmatch(resource, pattern)
            for pattern in cap.allowed_resources
            if resource and ("/" in pattern or "." in pattern)
        )

    def _sign(self, body: str) -> str:
        digest = hmac.new(
            self.config.secret_key.encode("utf-8"), body.encode("ascii"), hashlib.sha256
        ).digest()
        return _b64encode(digest)
