"""Core C10 - Experimental evaluation harness.

Runs the controlled scenarios against AEGIS and both baselines, tunes the risk
model on the validation split, freezes it, then reports held-out test results.
Every AEGIS decision is written to the audit log for reproducibility.
"""

from __future__ import annotations

import json
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

from .audit import AuditLogger
from .baselines import StaticPermissionAgent, UnprotectedAgent
from .config import Config, DATA_DIR
from .decision import Decision
from .gateway import AegisGateway
from .models import Scenario, ScenarioAction
from .risk import RiskEngine
from .scenarios import build_scenarios, scenario_stats, split_scenarios


@dataclass
class Record:
    """One labelled decision used in metric computation."""

    scenario_id: str
    category: str
    attack_type: str
    expected: str
    decision: Decision


def _safe_div(num: float, den: float) -> float:
    return round(num / den, 4) if den else 0.0


def compute_metrics(records: Sequence[Record], scenarios: Sequence[Scenario]) -> Dict[str, object]:
    """Compute security, utility and performance metrics from labelled records."""
    tp = sum(1 for r in records if r.expected == "DENY" and r.decision.outcome == "DENY")
    fp = sum(1 for r in records if r.expected == "ALLOW" and r.decision.outcome == "DENY")
    tn = sum(1 for r in records if r.expected == "ALLOW" and r.decision.outcome == "ALLOW")
    fn = sum(1 for r in records if r.expected == "DENY" and r.decision.outcome == "ALLOW")

    blocking_rate = _safe_div(tp, tp + fn)
    fpr = _safe_div(fp, fp + tn)
    fnr = _safe_div(fn, tp + fn)
    precision = _safe_div(tp, tp + fp)
    recall = blocking_rate
    f1 = _safe_div(2 * precision * recall, precision + recall)

    # A legitimate task is complete when every action intended to be allowed
    # was actually allowed. Out-of-scope attempts in the same task do not count.
    legit_ids = [s.id for s in scenarios if s.category == "legitimate"]
    complete = 0
    for sid in legit_ids:
        task_records = [r for r in records if r.scenario_id == sid and r.expected == "ALLOW"]
        if task_records and all(r.decision.outcome == "ALLOW" for r in task_records):
            complete += 1
    completion = _safe_div(complete, len(legit_ids))

    latencies = sorted(r.decision.latency_ms for r in records)
    p95 = latencies[min(len(latencies) - 1, int(0.95 * len(latencies)))] if latencies else 0.0

    return {
        "actions": len(records),
        "tp_denied_unsafe": tp,
        "fp_denied_legitimate": fp,
        "tn_allowed_legitimate": tn,
        "fn_allowed_unsafe": fn,
        "blocking_rate": blocking_rate,
        "unsafe_action_success_rate": fnr,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "task_completion_rate": completion,
        "mean_decision_latency_ms": round(statistics.fmean(latencies), 4) if latencies else 0.0,
        "p95_decision_latency_ms": round(p95, 4),
    }


def _percent(value: float) -> str:
    return f"{value * 100:.1f}%"


def _run_baseline(system, scenarios: Sequence[Scenario], name: str) -> Tuple[List[Record], float]:
    records: List[Record] = []
    for scenario in scenarios:
        for index, action in enumerate(scenario.actions):
            task_id = f"BASE-{scenario.id}-{index}"
            system.register_task(scenario.description)
            decision = system.decide(task_id, action)
            records.append(
                Record(
                    scenario_id=scenario.id,
                    category=scenario.category,
                    attack_type=scenario.attack_type,
                    expected=action.expected,
                    decision=decision,
                )
            )
    return records, 0.0


def _run_aegis(gateway: AegisGateway, scenarios: Sequence[Scenario]) -> List[Record]:
    records: List[Record] = []
    for scenario in scenarios:
        task = gateway.register_task(scenario.description)
        for action in scenario.actions:
            decision = gateway.authorize(task.id, action.to_action(task.id))
            records.append(
                Record(
                    scenario_id=scenario.id,
                    category=scenario.category,
                    attack_type=scenario.attack_type,
                    expected=action.expected,
                    decision=decision,
                )
            )
    return records


def _tuning_samples(
    scenarios: Sequence[Scenario], config: Config
) -> List[Tuple[object, str]]:
    """Build labelled I/S/P samples from validation scenarios."""
    gateway = AegisGateway(config=config)
    samples = []
    for scenario in scenarios:
        task = gateway.register_task(scenario.description)
        assert task.intent is not None
        for action in scenario.actions:
            request = action.to_action(task.id)
            classification = gateway.classifier.classify_action(request)
            factors = gateway.risk.factors(request, task.intent, classification)
            samples.append((factors, action.expected))
    return samples


def run_evaluation(config: Config | None = None, save: bool = True) -> Dict[str, object]:
    """Execute the full FYP-I comparison and return/save the results."""
    config = config or Config()
    eval_config = Config(
        secret_key=config.secret_key,
        capability_ttl_minutes=config.capability_ttl_minutes,
        weight_intent=config.weight_intent,
        weight_sensitivity=config.weight_sensitivity,
        weight_privilege=config.weight_privilege,
        theta_allow=config.theta_allow,
        theta_deny=config.theta_deny,
        escalation_policy=config.escalation_policy,
        simulated_execution_ms=config.simulated_execution_ms,
        db_path=DATA_DIR / "evaluation.db",
        results_path=config.results_path,
        random_seed=config.random_seed,
    )

    validation = split_scenarios("validation")
    test = split_scenarios("test")
    started = time.time()

    # 1. Tune the risk model on the validation split only.
    risk_for_tuning = RiskEngine(eval_config)
    params = risk_for_tuning.tune(_tuning_samples(validation, eval_config), max_fpr=0.20)
    tuned_config = risk_for_tuning.apply_tuning(params)

    # 2. Validation metrics with initial and tuned parameters.
    initial_audit = AuditLogger(config=eval_config)
    initial_audit.clear()
    initial_records = _run_aegis(AegisGateway(config=eval_config, audit=initial_audit), validation)
    initial_metrics = compute_metrics(initial_records, validation)
    initial_audit.close()

    tuned_audit = AuditLogger(config=eval_config)
    tuned_audit.clear()
    tuned_validation_records = _run_aegis(
        AegisGateway(config=tuned_config, audit=tuned_audit), validation
    )
    tuned_validation_metrics = compute_metrics(tuned_validation_records, validation)
    tuned_audit.close()

    # 3. Held-out test evaluation. The tuned parameters are frozen here.
    test_audit = AuditLogger(config=eval_config)
    test_audit.clear()
    test_gateway = AegisGateway(config=tuned_config, audit=test_audit)
    aegis_records = _run_aegis(test_gateway, test)
    aegis_metrics = compute_metrics(aegis_records, test)
    chain_ok, broken = test_audit.verify_chain()
    test_audit.close()

    unprotected_records, _ = _run_baseline(UnprotectedAgent(), test, "Unprotected")
    unprotected_metrics = compute_metrics(unprotected_records, test)

    static_records, _ = _run_baseline(StaticPermissionAgent(eval_config), test, "StaticPermission")
    static_metrics = compute_metrics(static_records, test)

    # Overhead is decision cost relative to the simulated execution cost.
    overhead = round(
        100 * float(aegis_metrics["mean_decision_latency_ms"]) / eval_config.simulated_execution_ms,
        2,
    )

    results: Dict[str, object] = {
        "project": "AEGIS FYP-I core evaluation",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "seed": eval_config.random_seed,
        "corpus": scenario_stats(),
        "risk_tuning": params,
        "validation_before_tuning": initial_metrics,
        "validation_after_tuning": tuned_validation_metrics,
        "test_results": {
            "AEGIS": aegis_metrics,
            "Unprotected": unprotected_metrics,
            "StaticPermission": static_metrics,
        },
        "overhead_vs_simulated_execution_percent": overhead,
        "audit_chain_valid": chain_ok,
        "audit_broken_events": broken,
        "runtime_seconds": round(time.time() - started, 3),
        "decisions": [
            {
                "scenario": r.scenario_id,
                "category": r.category,
                "attack": r.attack_type,
                "expected": r.expected,
                "outcome": r.decision.outcome,
                "rule": r.decision.policy.rule_id,
                "risk_score": r.decision.risk.score if r.decision.risk else None,
                "latency_ms": round(r.decision.latency_ms, 4),
            }
            for r in aegis_records
        ],
    }

    if save:
        path = Path(config.results_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    return results


def format_summary(results: Dict[str, object]) -> str:
    """Return a compact human-readable summary of an evaluation result."""
    lines = [
        "AEGIS FYP-I evaluation summary",
        "=" * 32,
        f"Corpus: {results['corpus']}",
        f"Tuned weights: I={results['risk_tuning']['weight_intent']}, "
        f"S={results['risk_tuning']['weight_sensitivity']}, "
        f"P={results['risk_tuning']['weight_privilege']}; "
        f"thresholds={results['risk_tuning']['theta_allow']}/"
        f"{results['risk_tuning']['theta_deny']}",
        f"Validation FPR before/after tuning: "
        f"{results['validation_before_tuning']['false_positive_rate']}/"
        f"{results['validation_after_tuning']['false_positive_rate']}",
        "",
        f"{'System':<18} {'Block':>7} {'FPR':>7} {'FNR':>7} {'F1':>7} {'Complete':>9} {'p95 ms':>8}",
    ]
    for name, metrics in results["test_results"].items():  # type: ignore[union-attr]
        lines.append(
            f"{name:<18} {_percent(float(metrics['blocking_rate'])):>7} "
            f"{_percent(float(metrics['false_positive_rate'])):>7} "
            f"{_percent(float(metrics['false_negative_rate'])):>7} "
            f"{float(metrics['f1']):>7.3f} "
            f"{_percent(float(metrics['task_completion_rate'])):>9} "
            f"{float(metrics['p95_decision_latency_ms']):>8.3f}"
        )
    lines.append("")
    lines.append(f"Audit chain valid: {results['audit_chain_valid']}")
    lines.append(f"Overhead vs simulated execution: {results['overhead_vs_simulated_execution_percent']}%")
    return "\n".join(lines)
