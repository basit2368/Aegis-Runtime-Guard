# AEGIS — FYP-I Core Prototype

**Agentic Execution Guard and Intelligent Security**  
An intent-aware runtime security and authorization framework for autonomous AI agents.

This repository contains the **FYP-I committed implementation**: core components C1–C10, the two baseline systems, a tuned contextual risk model, hash-chained provenance logging, a controlled agent environment, an operator dashboard and an evaluation harness. Stretch components S1–S5 are deliberately deferred to FYP-II.

---

## 1. What is implemented in FYP-I

| Proposal ID | Committed component | Implementation |
|---|---|---|
| C1 | Agent Gateway | `aegis/gateway.py` — single interception point for every protected action |
| C2 | Intent Analyzer | `aegis/intent.py` — deterministic extraction; optional LLM adapter with safe fallback |
| C3 | Capability Manager | `aegis/capability.py` — signed, scoped, expiring, revocable capability tokens |
| C4 | Policy Engine | `aegis/policy.py` — deterministic rules with hard-deny precedence and full trace |
| C5 | Resource Sensitivity Classification | `aegis/resources.py` — LOW / MEDIUM / HIGH / CRITICAL patterns |
| C6 | Risk Engine | `aegis/risk.py` — `R = wI·I + wS·S + wP·P`, validation-set tuning |
| C7 | Allow/Deny Decision Engine | `aegis/decision.py` — combines capability, policy and risk; fails closed |
| C8 | Provenance & Audit Logging | `aegis/audit.py` — SQLite hash chain, tamper detection |
| C9 | Baseline Systems | `aegis/baselines.py` — unprotected and static-permission agents |
| C10 | Experimental Evaluation | `aegis/scenarios.py`, `aegis/evaluation.py` — 12 scenarios, 51 labelled actions |

Supporting deliverables: controlled executor (`aegis/executor.py`), operator dashboard (`aegis/dashboard.py`), CLI (`aegis/cli.py`) and unit/integration tests (`aegis/tests/`).

---

## 2. Quick start

Python 3.10 or newer is required. **No third-party packages are needed** for the core prototype, evaluation or dashboard.

```powershell
cd "D:\AEGIS FYP"

# Interactive demo: register a task, intercept six actions, print decisions
python run_demo.py demo

# Full evaluation (tunes on validation, reports held-out test results)
python run_demo.py evaluate

# Operator dashboard at http://127.0.0.1:8766
python run_dashboard.py

# Unit and integration tests
python -m unittest discover -s aegis/tests -v
```

Equivalent module form: `python -m aegis.cli demo|evaluate|reset|dashboard`.

`python run_demo.py reset` clears the demo audit log. Evaluation uses a separate database (`data/evaluation.db`) so it never overwrites your interactive audit trail.

---

## 3. Decision pipeline

For every intercepted action:

1. **Gateway** normalizes the action (e.g. `pytest tests/test_auth.py` → executable `pytest`, full command retained in parameters).
2. **Capability Manager** verifies the HMAC signature, expiry, revocation status and scope.
3. **Resource Classifier** assigns LOW / MEDIUM / HIGH / CRITICAL.
4. **Policy Engine** evaluates deterministic rules such as critical-resource deny, deletion outside intent, denied operations, scope violations and untrusted-content effects. Any DENY is a **hard deny**.
5. **Risk Engine** computes intent deviation `I`, sensitivity `S`, privilege `P` and `R = wI·I + wS·S + wP·P`.
6. **Decision Engine** returns ALLOW or DENY. The FYP-I escalation band fails closed because human approval is a stretch feature.
7. **Audit Logger** records the task, capability, decision, policy trace, risk factors and execution outcome in a hash-chained SQLite log.

Example: reading `.env` during a bug-fix task → `DENY` by rule `P004` (CRITICAL resource not explicitly named), with `I=1.0, S=1.0, P=0.1, R=0.82`.

---

## 4. Evaluation results (FYP-I)

FYP-I prototype corpus: **12 scenarios / 51 labelled actions** (27 validation, 24 held-out test; 27 legitimate, 24 adversarial). Risk parameters are tuned only on the validation split, then frozen for the test split. The full benchmark suite (at least 30 legitimate and 30 adversarial cases, with statistical hypothesis testing) is planned for FYP-II.

Tuned model: `wI=0.30, wS=0.50, wP=0.20`, `θ_allow=0.45`, `θ_deny=0.50`.

| System | Unsafe blocked | False-positive rate | FNR | F1 | Legitimate task completion | p95 decision latency |
|---|---:|---:|---:|---:|---:|---:|
| **AEGIS (tuned)** | 100.0% | 0.0% | 0.0% | 1.000 | 100.0% | ≈0.6–0.8 ms |
| Static-permission baseline | 92.3% | 9.1% | 7.7% | 0.923 | 100.0% | ≈0.3–0.5 ms |
| Unprotected baseline | 0.0% | 0.0% | 100.0% | 0.000 | 100.0% | 0.00 ms |

Decision overhead relative to the simulated 5 ms execution cost: **≈7–10%** (timing varies per run). Audit hash chain: **valid**. Full machine-readable results for the latest run: `data/evaluation_results.json`.

> These results demonstrate the prototype on a **small, controlled scenario corpus**. They are not a claim of general real-world agent security. FYP-II will expand this into a benchmark suite of at least 30 legitimate and 30 adversarial cases and add full statistical analysis.

---

## 5. Project structure

```text
D:\AEGIS FYP\
├── aegis/
│   ├── __init__.py          package metadata
│   ├── config.py            environment-driven configuration
│   ├── models.py            tasks, intents, capabilities, actions, decisions
│   ├── intent.py            C2 intent analyzer (+ optional LLM adapter)
│   ├── capability.py        C3 signed capability tokens
│   ├── policy.py            C4 deterministic policy rules
│   ├── resources.py         C5 sensitivity classifier
│   ├── risk.py              C6 risk model and validation-set tuning
│   ├── decision.py          C7 decision engine
│   ├── audit.py             C8 hash-chained audit log
│   ├── gateway.py           C1 agent gateway
│   ├── executor.py          simulated controlled tool environment
│   ├── baselines.py         C9 baseline agents
│   ├── scenarios.py         C10 controlled scenario corpus
│   ├── evaluation.py        C10 metrics, tuning and comparison
│   ├── dashboard.py         operator web console (stdlib)
│   ├── cli.py               command-line interface
│   └── tests/test_core.py   unit/integration tests
├── data/                    generated audit DB and evaluation results
├── run_demo.py              CLI launcher
├── run_dashboard.py         dashboard launcher
└── README.md
```

---

## 6. Configuration

All settings can be overridden with environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `AEGIS_SECRET` | `aegis-fyp1-demo-secret` | HMAC key for capability tokens (set a real secret outside demos) |
| `AEGIS_CAPABILITY_TTL` | `30` | Capability lifetime in minutes |
| `AEGIS_W_INTENT`, `AEGIS_W_SENS`, `AEGIS_W_PRIV` | `0.5, 0.3, 0.2` | Initial risk weights |
| `AEGIS_THETA_ALLOW`, `AEGIS_THETA_DENY` | `0.35, 0.65` | Initial decision thresholds |
| `AEGIS_ESCALATION` | `deny` | FYP-I behaviour for the escalation band |
| `AEGIS_EXECUTION_MS` | `5` | Simulated execution cost used for overhead measurement |
| `AEGIS_DB` | `data/aegis.db` | Demo audit database |
| `AEGIS_RESULTS` | `data/evaluation_results.json` | Evaluation output path |
| `AEGIS_SEED` | `42` | Reproducibility seed |

---

## 7. Deliberately deferred to FYP-II

- **S1** Behavioural anomaly detection over action trajectories
- **S2** Sandboxed execution (Docker/gVisor/Firecracker)
- **S3** Human-in-the-loop approval for the escalation band
- **S4** Advanced browser / external-content monitoring
- **S5** Adaptive capability revocation
- Full statistical hypothesis testing (H1 vs H0) and answers to RQ1–RQ6 on a larger corpus

The decision engine already exposes an `ESCALATE` outcome; FYP-I maps it to DENY, so FYP-II can attach approval without changing the authorization pipeline.
