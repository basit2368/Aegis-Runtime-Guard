"""Unit and integration tests for the AEGIS FYP-I core prototype."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from aegis.audit import AuditLogger
from aegis.baselines import StaticPermissionAgent, UnprotectedAgent
from aegis.capability import CapabilityManager
from aegis.config import Config
from aegis.decision import DecisionEngine
from aegis.gateway import AegisGateway
from aegis.intent import IntentAnalyzer
from aegis.models import ActionRequest, Capability, IntentProfile, PolicyResult, Task
from aegis.policy import PolicyEngine
from aegis.resources import ResourceClassifier
from aegis.risk import RiskEngine
from aegis.scenarios import build_scenarios, scenario_stats


class AegisTestCase(unittest.TestCase):
    """Base test case with an isolated temporary audit database."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "test.db"
        self.config = Config(db_path=self.db, secret_key="test-secret")
        self.audit = AuditLogger(config=self.config)
        self.gateway = AegisGateway(config=self.config, audit=self.audit)

    def tearDown(self) -> None:
        self.audit.close()
        self.tmp.cleanup()


class FailingLLM:
    """LLM adapter stub that always fails."""

    def analyze(self, description: str) -> str:
        raise RuntimeError("offline")


class InvalidJSONLLM:
    """LLM adapter stub that returns a structurally invalid profile."""

    def analyze(self, description: str) -> str:
        return '{"expected_operations": "not-a-list"}'


class TestIntentAnalyzer(AegisTestCase):
    def test_extracts_operations_and_secrets(self) -> None:
        profile = self.gateway.intent_analyzer.analyze(
            Task(id="T1", description="Fix the authentication bug and run tests")
        )
        self.assertIn("READ", profile.expected_operations)
        self.assertIn("WRITE", profile.expected_operations)
        self.assertIn("EXECUTE", profile.expected_operations)
        self.assertIn("DELETE", profile.prohibited_operations)
        self.assertTrue(any(".env" in p for p in profile.prohibited_resources))
        self.assertEqual(profile.source, "deterministic")

    def test_default_profile_is_safe(self) -> None:
        profile = IntentAnalyzer().analyze_deterministic("Look at the notes")
        self.assertEqual(profile.expected_operations, {"READ"})
        self.assertIn("DELETE", profile.prohibited_operations)

    def test_llm_failure_falls_back_and_records_reason(self) -> None:
        analyzer = IntentAnalyzer(FailingLLM())
        profile = analyzer.analyze(
            Task(id="T2", description="Fix the authentication bug and run tests")
        )
        self.assertEqual(profile.source, "fallback")
        self.assertIn("offline", profile.fallback_reason)
        self.assertIn("READ", profile.expected_operations)
        self.assertIn("WRITE", profile.expected_operations)

    def test_invalid_llm_json_falls_back(self) -> None:
        analyzer = IntentAnalyzer(InvalidJSONLLM())
        profile = analyzer.analyze(Task(id="T3", description="Fix the authentication bug"))
        self.assertEqual(profile.source, "fallback")
        self.assertIn("invalid", profile.fallback_reason)
        self.assertIn("READ", profile.expected_operations)


class TestCapabilityManager(AegisTestCase):
    def test_signature_tampering_is_rejected(self) -> None:
        task = self.gateway.register_task("Fix the bug and run tests")
        cap = self.gateway.capability_for(task.id)
        body, sig = cap.token.rsplit(".", 1)
        tampered = body + "." + ("A" if sig[0] != "A" else "B") + sig[1:]
        valid, reason = self.gateway.capabilities.validate(tampered)
        self.assertIsNone(valid)
        self.assertIn("signature", reason.lower())

    def test_expiry_and_revocation(self) -> None:
        config = Config(db_path=self.db, secret_key="test-secret", capability_ttl_minutes=0)
        audit = AuditLogger(config=config)
        gateway = AegisGateway(config=config, audit=audit)
        task = gateway.register_task("Fix the bug")
        cap = gateway.capability_for(task.id)
        self.assertIsNone(gateway.capabilities.validate(cap.token)[0])
        audit.close()

        task2 = self.gateway.register_task("Read the documentation")
        cap2 = self.gateway.capability_for(task2.id)
        self.assertTrue(self.gateway.capabilities.revoke(cap2.token))
        valid, reason = self.gateway.capabilities.validate(cap2.token)
        self.assertIsNone(valid)
        self.assertIn("revoked", reason.lower())

    def test_scope_matching(self) -> None:
        task = self.gateway.register_task("Fix the authentication bug and run tests")
        cap = self.gateway.capability_for(task.id)
        self.assertTrue(CapabilityManager.resource_allowed(cap, "src/auth/login.py"))
        self.assertFalse(CapabilityManager.resource_allowed(cap, ".env"))
        self.assertFalse(CapabilityManager.explicitly_allows(cap, ".env"))

    def test_is_expired_honours_explicit_epoch_zero(self) -> None:
        cap = Capability(
            token="dummy",
            task_id="T1",
            allowed_operations={"READ"},
            allowed_resources=["docs/*"],
            denied_resources=[],
            network_policy="restricted",
            issued_at=0.0,
            expires_at=100.0,
        )
        self.assertFalse(cap.is_expired(at=0.0))
        self.assertFalse(cap.is_expired(at=99.9))
        self.assertTrue(cap.is_expired(at=100.0))
        self.assertTrue(cap.is_expired(at=200.0))

    def test_cross_task_capability_reuse_is_rejected(self) -> None:
        task_a = self.gateway.register_task("Fix the bug and run tests")
        task_b = self.gateway.register_task("Read the documentation")
        cap_a = self.gateway.capability_for(task_a.id)
        valid, reason = self.gateway.capabilities.validate(cap_a.token, task_id=task_a.id)
        self.assertIsNotNone(valid)
        self.assertIn("valid", reason.lower())
        valid, reason = self.gateway.capabilities.validate(cap_a.token, task_id=task_b.id)
        self.assertIsNone(valid)
        self.assertIn("task", reason.lower())


class TestPolicyAndRisk(AegisTestCase):
    def test_critical_resource_is_hard_denied(self) -> None:
        task = self.gateway.register_task("Fix the authentication bug")
        cap = self.gateway.capability_for(task.id)
        action = ActionRequest(task.id, "filesystem", "READ", ".env")
        classification = self.gateway.classifier.classify_action(action)
        result = self.gateway.policy.evaluate(action, task.intent, cap, classification)
        self.assertTrue(result.denied)
        self.assertEqual(result.rule_id, "P004")

    def test_hard_deny_overrides_high_risk_allow(self) -> None:
        decision_engine = DecisionEngine(RiskEngine(self.config), self.config)
        policy = PolicyResult("DENY", "P004", "critical resource", [])
        risk = self.gateway.risk.evaluate(
            ActionRequest("T", "filesystem", "READ", "docs/a.md"),
            IntentProfile("test", {"READ"}, ["docs/*"]),
        )
        decision = decision_engine.decide(
            ActionRequest("T", "filesystem", "READ", "docs/a.md"),
            IntentProfile("test", {"READ"}, ["docs/*"]),
            None,
            "invalid",
            policy,
            risk,
        )
        self.assertEqual(decision.outcome, "DENY")

    def test_risk_formula_and_thresholds(self) -> None:
        engine = RiskEngine(self.config)
        factors = engine.factors(
            ActionRequest("T", "filesystem", "READ", "docs/a.md"),
            IntentProfile("task", {"READ"}, ["docs/*"]),
        )
        expected = (
            self.config.weight_intent * factors.intent_deviation
            + self.config.weight_sensitivity * factors.sensitivity
            + self.config.weight_privilege * factors.privilege
        )
        self.assertAlmostEqual(engine.score(factors), round(expected, 4), places=3)
        self.assertEqual(engine.outcome(0.1), "ALLOW")
        self.assertEqual(engine.outcome(0.9), "DENY")
        self.assertEqual(engine.outcome(0.5), "ESCALATE")

    def test_classifier_levels(self) -> None:
        classifier = ResourceClassifier()
        self.assertEqual(classifier.classify("docs/api.md").label, "LOW")
        self.assertEqual(classifier.classify("src/app.py").label, "MEDIUM")
        self.assertEqual(classifier.classify("config/settings.json").label, "HIGH")
        self.assertEqual(classifier.classify("ssh/id_rsa").label, "CRITICAL")
        self.assertEqual(classifier.classify("unknown.bin").label, "MEDIUM")

    def test_tuning_returns_normalised_parameters(self) -> None:
        engine = RiskEngine(self.config)
        factors = engine.factors(
            ActionRequest("T", "filesystem", "READ", "docs/a.md"),
            IntentProfile("t", {"READ"}, ["docs/*"]),
        )
        params = engine.tune([(factors, "ALLOW"), (factors, "DENY")])
        total = (
            float(params["weight_intent"])
            + float(params["weight_sensitivity"])
            + float(params["weight_privilege"])
        )
        self.assertAlmostEqual(total, 1.0)
        self.assertLess(float(params["theta_allow"]), float(params["theta_deny"]))


class TestAudit(AegisTestCase):
    def test_hash_chain_detects_tampering(self) -> None:
        self.audit.log("TEST", {"value": 1})
        self.audit.log("TEST", {"value": 2})
        ok, broken = self.audit.verify_chain()
        self.assertTrue(ok)
        self.assertEqual(broken, [])

        conn = sqlite3.connect(self.db)
        conn.execute("UPDATE audit_events SET payload = ? WHERE seq = 1", (json.dumps({"value": 99}),))
        conn.commit()
        conn.close()
        ok, broken = self.audit.verify_chain()
        self.assertFalse(ok)
        self.assertEqual(len(broken), 1)

    def test_decisions_are_logged(self) -> None:
        task = self.gateway.register_task("Fix the bug and run tests")
        before = self.audit.count()
        self.gateway.handle(task.id, "filesystem", "READ", "src/app.py", execute=False)
        self.assertGreater(self.audit.count(), before)
        ok, _ = self.audit.verify_chain()
        self.assertTrue(ok)


class TestGatewayIntegration(AegisTestCase):
    def test_allow_and_deny_paths(self) -> None:
        task = self.gateway.register_task("Fix the authentication bug and run tests")
        allowed = self.gateway.handle(task.id, "filesystem", "READ", "src/auth/login.py")
        denied = self.gateway.handle(task.id, "filesystem", "READ", ".env")
        self.assertEqual(allowed.outcome, "ALLOW")
        self.assertTrue(allowed.executed)
        self.assertEqual(denied.outcome, "DENY")
        self.assertFalse(denied.executed)
        self.assertIn("P004", denied.explanation)

    def test_revocation_applies_to_next_action(self) -> None:
        task = self.gateway.register_task("Read the documentation")
        self.assertTrue(self.gateway.revoke_capability(task.id))
        decision = self.gateway.handle(task.id, "filesystem", "READ", "README.md")
        self.assertEqual(decision.outcome, "DENY")
        self.assertIn("Capability invalid", decision.reason)

    def test_execute_normalises_terminal_command(self) -> None:
        task = self.gateway.register_task("Fix the bug and run tests")
        decision = self.gateway.handle(
            task.id, "terminal", "EXECUTE", "pytest tests/test_auth.py", execute=True
        )
        normalised = ActionRequest("T", "terminal", "EXECUTE", "pytest tests/test_auth.py")
        self.assertEqual(normalised.resource, "pytest")
        self.assertEqual(normalised.params["command"], "pytest tests/test_auth.py")
        self.assertEqual(decision.outcome, "ALLOW")
        self.assertEqual(decision.execution_result["exit_code"], 0)
        self.assertEqual(decision.execution_result["command"], "pytest tests/test_auth.py")

    def test_all_scenarios_match_ground_truth(self) -> None:
        for scenario in build_scenarios():
            task = self.gateway.register_task(scenario.description)
            for action in scenario.actions:
                decision = self.gateway.authorize(task.id, action.to_action(task.id))
                self.assertEqual(
                    decision.outcome,
                    action.expected,
                    f"{scenario.id}: {action.operation} {action.resource} -> "
                    f"{decision.outcome} ({decision.policy.rule_id})",
                )

    def test_scenario_corpus_is_split(self) -> None:
        stats = scenario_stats()
        self.assertEqual(stats["scenarios"], 12)
        self.assertEqual(stats["validation_actions"] + stats["test_actions"], stats["actions"])


class TestBaselines(AegisTestCase):
    def test_unprotected_allows_everything(self) -> None:
        baseline = UnprotectedAgent()
        action = next(a for s in build_scenarios() if s.category == "adversarial" for a in s.actions)
        self.assertEqual(baseline.decide("B", action).outcome, "ALLOW")

    def test_static_denies_critical_but_is_not_intent_aware(self) -> None:
        baseline = StaticPermissionAgent(self.config)
        critical = ActionRequest("B", "filesystem", "READ", ".env")
        self.assertEqual(
            baseline.decide("B", build_scenarios()[0].actions[0]).outcome, "ALLOW"
        )
        self.assertEqual(baseline.classifier.classify_action(critical).label, "CRITICAL")


class TestDashboard(AegisTestCase):
    def test_frontend_wraps_parameter_json_parsing(self) -> None:
        from aegis import dashboard

        source = Path(dashboard.__file__).read_text(encoding="utf-8")
        self.assertIn("JSON.parse", source)
        self.assertIn("try {", source)
        self.assertIn("Invalid parameters JSON", source)

    def test_malformed_request_body_returns_clean_error(self) -> None:
        import http.client
        import threading
        from http.server import ThreadingHTTPServer

        from aegis.dashboard import AegisHandler

        handler = type("TestBoundHandler", (AegisHandler,), {
            "gateway": self.gateway,
            "config": self.config,
        })
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        conn = None
        try:
            conn = http.client.HTTPConnection(
                "127.0.0.1", server.server_address[1], timeout=5
            )
            conn.request(
                "POST", "/api/actions", body="{not-json",
                headers={"Content-Type": "application/json"},
            )
            response = conn.getresponse()
            payload = json.loads(response.read().decode("utf-8"))
            self.assertEqual(response.status, 400)
            self.assertIn("error", payload)
        finally:
            if conn is not None:
                conn.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
