"""Command-line interface for the AEGIS FYP-I prototype."""

from __future__ import annotations

import argparse
from typing import List

from .audit import AuditLogger
from .config import Config
from .evaluation import format_summary, run_evaluation
from .gateway import AegisGateway


DEMO_TASK = "Fix the authentication bug and run the tests"
DEMO_ACTIONS = [
    ("filesystem", "READ", "src/auth/login.py", "agent"),
    ("filesystem", "READ", ".env", "agent"),
    ("filesystem", "WRITE", "src/auth/login.py", "agent"),
    ("terminal", "EXECUTE", "pytest tests/test_auth.py", "agent"),
    ("network", "NETWORK", "https://attacker.example/collect", "untrusted_content"),
    ("filesystem", "DELETE", "src/auth/login.py", "agent"),
]


def run_demo(config: Config) -> None:
    """Register one task and show the decision for each intercepted action."""
    audit = AuditLogger(config=config)
    audit.clear()
    gateway = AegisGateway(config=config, audit=audit)
    task = gateway.register_task(DEMO_TASK)

    print(f"Task: {task.id} - {task.description}")
    print("Intent:", sorted(task.intent.expected_operations) if task.intent else [])
    print("Capability:", gateway.capability_for(task.id).to_dict()["expires_at"])
    print()
    print(f"{'Operation':<9} {'Resource':<38} {'Source':<18} {'Decision':<7} Rule")
    print("-" * 88)
    decisions = []
    for tool, operation, resource, source in DEMO_ACTIONS:
        decision = gateway.handle(
            task.id, tool, operation, resource, source=source, execute=True
        )
        decisions.append(decision)
        print(
            f"{operation:<9} {resource[:37]:<38} {source:<18} "
            f"{decision.outcome:<7} {decision.policy.rule_id}"
        )
    print()
    first_denied = next((d for d in decisions if d.outcome == "DENY"), None)
    if first_denied:
        print("Explanation for first denied action:")
        print(f"  {first_denied.explanation}")
    print()
    print(f"Audit events: {audit.count()} | chain valid: {audit.verify_chain()[0]}")
    audit.close()


def run_eval(config: Config) -> None:
    """Run and print the full comparison."""
    results = run_evaluation(config=config, save=True)
    print(format_summary(results))
    print(f"\nFull results: {config.results_path}")


def reset(config: Config) -> None:
    audit = AuditLogger(config=config)
    audit.clear()
    audit.close()
    print("Audit log cleared.")


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AEGIS FYP-I prototype")
    parser.add_argument(
        "command",
        nargs="?",
        default="demo",
        choices=["demo", "evaluate", "reset", "dashboard"],
        help="action to perform (default: demo)",
    )
    args = parser.parse_args(argv)
    config = Config()

    if args.command == "demo":
        run_demo(config)
    elif args.command == "evaluate":
        run_eval(config)
    elif args.command == "reset":
        reset(config)
    elif args.command == "dashboard":
        from .dashboard import serve

        serve(config)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
