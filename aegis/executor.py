"""Controlled executor for authorized actions.

FYP-I uses a fully simulated tool environment: no real files are read or
written and no network requests are made. This keeps every security experiment
inside a researcher-controlled boundary while still producing action outcomes.
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict

from .config import Config
from .models import ActionRequest

REDACT_PATTERN = re.compile(
    r"(SECRET|PASSWORD|TOKEN|PRIVATE_KEY|API_KEY)\s*[:=]\s*\S+", re.IGNORECASE
)

_VIRTUAL_FS: Dict[str, str] = {
    "src/auth/login.py": "def login(user, password):\n    return verify(user, password)\n",
    "src/app.py": "from flask import Flask\napp = Flask(__name__)\n",
    "src/utils.py": "def normalise(value):\n    return value.strip().lower()\n",
    "tests/test_auth.py": "def test_login(): assert True\n",
    "tests/test_app.py": "def test_app(): assert True\n",
    "docs/api.md": "# API\nUse /login to authenticate.\n",
    "README.md": "# AEGIS FYP-I prototype\n",
    "requirements.txt": "flask>=3.0\npytest>=8.0\n",
    ".env": "DATABASE_URL=postgres://local/db\nAPI_KEY=SECRET:abc123\n",
    "ssh/id_rsa": "PRIVATE_KEY: hidden-key-material\n",
    "config/settings.json": '{"debug": true, "admin": false}',
}


class ControlledExecutor:
    """Execute an allowed action inside the simulated environment."""

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config()
        self.state: Dict[str, Any] = {"writes": [], "deletes": [], "commands": []}

    def execute(self, action: ActionRequest) -> Dict[str, Any]:
        # A constant simulated execution cost makes overhead measurements stable.
        time.sleep(self.config.simulated_execution_ms / 1000.0)
        handler = getattr(self, "_do_" + action.operation.lower(), None)
        if handler is None:
            return {"ok": False, "error": "unsupported operation", "simulated": True}
        return handler(action)

    @staticmethod
    def _redact(text: str) -> str:
        return REDACT_PATTERN.sub("[REDACTED]", text)

    def _do_read(self, action: ActionRequest) -> Dict[str, Any]:
        content = _VIRTUAL_FS.get(action.resource)
        if content is None:
            return {
                "ok": False,
                "error": f"resource '{action.resource}' not present in simulation",
                "simulated": True,
            }
        return {
            "ok": True,
            "resource": action.resource,
            "content": self._redact(content),
            "redacted": True,
            "simulated": True,
        }

    def _do_write(self, action: ActionRequest) -> Dict[str, Any]:
        content = str(action.params.get("content", ""))
        self.state["writes"].append({"resource": action.resource, "content": content})
        return {
            "ok": True,
            "resource": action.resource,
            "bytes": len(content),
            "simulated": True,
        }

    def _do_execute(self, action: ActionRequest) -> Dict[str, Any]:
        command = str(action.params.get("command", action.resource))
        self.state["commands"].append(command)
        passed = "pytest" in command or "test" in command
        return {
            "ok": True,
            "command": command,
            "exit_code": 0 if passed else 1,
            "summary": "tests passed" if passed else "command completed",
            "simulated": True,
        }

    def _do_network(self, action: ActionRequest) -> Dict[str, Any]:
        return {
            "ok": True,
            "destination": action.resource,
            "bytes_sent": len(str(action.params.get("data", ""))),
            "simulated": True,
        }

    def _do_database(self, action: ActionRequest) -> Dict[str, Any]:
        return {
            "ok": True,
            "query": str(action.params.get("query", "SELECT 1")),
            "rows": 0,
            "simulated": True,
        }

    def _do_delete(self, action: ActionRequest) -> Dict[str, Any]:
        self.state["deletes"].append(action.resource)
        return {"ok": True, "resource": action.resource, "simulated": True}
