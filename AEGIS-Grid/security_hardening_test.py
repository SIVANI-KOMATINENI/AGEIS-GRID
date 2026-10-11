"""
security_hardening_test.py
Phase B Security Hardening Regression Tests for AEGIS Grid.

Tests cover:
1. Authority & Provenance Enforcement: Forged tokens, missing tokens, mismatched run IDs,
   unauthorized actions, report reuse, and database unavailability (fail-closed).
2. Elimination of Fail-Open Policy: Unknown action types, priority bypass on normal telemetry,
   and safe actions with forged authorization.
3. LLM Hallucination Safety: LLM anomaly hallucination over healthy microgrid telemetry,
   preserving deterministic physical authority, and schema validation.
4. Replay Protection: Duplicate observations, timestamp regression, session rollover isolation,
   and untrusted observation exclusion from baseline history.
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from agents.schemas import (
    MonitoringInput,
    MonitoringReport,
    ProposedAction,
    ResponseInput,
    compute_action_digest,
)
from agents.monitoring_agent import _merge_diagnoses, run_monitoring_agent
from agents.response_agent import run_response_agent, _sanitize_action, _deterministic_response
from aegis.policy import verify_policy, PolicyResult
from aegis.provenance import verify_provenance, ProvenanceResult
from aegis.behaviour import analyze_behaviour, BehaviourResult, reset_behaviour_history
from aegis.risk import evaluate_risk, RiskResult
from aegis.controller import make_decision, FinalDecision
from database.models import ObservationRow, ReplayCheckResult, AEGISDecisionRow
from database.sqlite import (
    check_observation_replay,
    record_observation_with_replay_check,
    start_simulation_session,
    query_recent_observations,
    init_db,
    persist_decision_and_consume_report,
    sync_neo4j_outbox,
    is_report_consumed,
)
from provenance.neo4j_client import Neo4jClient


class AuthorityAndProvenanceRegressionTest(unittest.TestCase):
    """P0 Regression tests: Authority and provenance enforcement."""

    def setUp(self):
        reset_behaviour_history()
        self.action = ProposedAction(
            action_id="act_12:00",
            run_id="run_auth_100",
            action_type="ISOLATE_BATTERY",
            target="battery_1",
            reason="Emergency isolation proposed",
            priority="HIGH",
            claimed_authorization="rep_12:00",
        )

    def test_forged_token_is_hard_blocked_by_policy_and_controller(self):
        """Vulnerability: An attacker providing auth_tok_hacked_admin_999 must be BLOCKED, never ALLOW."""
        forged_action = self.action.model_copy(
            update={"claimed_authorization": "auth_tok_hacked_admin_999"}
        )

        pol = verify_policy(forged_action)
        self.assertEqual(pol.decision, "block")
        self.assertEqual(pol.matched_rule_id, "rule_000_forged_auth")

        prov = verify_provenance(forged_action)
        self.assertFalse(prov.verified)

        beh = analyze_behaviour(forged_action)
        risk = evaluate_risk(pol, prov, beh)
        decision = make_decision(forged_action, pol, prov, beh, risk)

        self.assertEqual(decision.final_decision, "block")
        self.assertIn("rule_000_forged_auth", decision.reason)

    def test_missing_authorization_on_severe_action_is_blocked(self):
        """Vulnerability: Severe actions proposed without claimed authorization must be BLOCKED."""
        missing_auth = self.action.model_copy(update={"claimed_authorization": None})

        pol = verify_policy(missing_auth)
        self.assertEqual(pol.decision, "block")
        self.assertEqual(pol.matched_rule_id, "rule_004")

        prov = verify_provenance(missing_auth)
        self.assertFalse(prov.verified)
        self.assertEqual(prov.status, "invalid_claim")

        beh = analyze_behaviour(missing_auth)
        risk = evaluate_risk(pol, prov, beh)
        decision = make_decision(missing_auth, pol, prov, beh, risk)

        self.assertEqual(decision.final_decision, "block")

    def test_mismatched_run_id_is_blocked(self):
        """Vulnerability: Reusing a report from another run (cross-run spoofing) must be BLOCKED."""
        action_diff_run = self.action.model_copy(update={"run_id": "run_other_999"})

        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        session = Mock()
        client.driver.session.return_value.__enter__.return_value = session
        # Simulate report existing under run_100, but action under run_other_999
        session.run.return_value.single.return_value = {
            "report_exists": False,
            "report_exists_anywhere": True,
            "monitoring_link_exists": False,
            "response_link_exists": False,
            "action_exists": False,
            "claim_matches": False,
            "report_reused": False,
        }

        with patch("aegis.provenance.get_neo4j_client", return_value=client):
            prov = verify_provenance(action_diff_run)

        self.assertFalse(prov.verified)
        self.assertEqual(prov.status, "mismatched_run_id")

        pol = PolicyResult(decision="allow", matched_rule_id="rule_002_emergency", reason="Emergency ok")
        beh = BehaviourResult(flagged=False, score=0.0)
        risk = evaluate_risk(pol, prov, beh)
        decision = make_decision(action_diff_run, pol, prov, beh, risk)

        self.assertEqual(decision.final_decision, "block")
        self.assertIn("Provenance Denied", decision.reason)

    def test_unauthorized_action_under_normal_report_is_blocked(self):
        """Vulnerability: Claiming a valid report ID where the report status was NORMAL must be BLOCKED."""
        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        session = Mock()
        client.driver.session.return_value.__enter__.return_value = session
        session.run.return_value.single.return_value = {
            "report_exists": True,
            "report_exists_anywhere": True,
            "monitoring_link_exists": True,
            "response_link_exists": True,
            "action_exists": True,
            "claim_matches": True,
            "report_status": "NORMAL",
            "action_type": "ISOLATE_BATTERY",
            "report_reused": False,
        }

        # Action proposes ISOLATE_BATTERY, but report was NORMAL
        status = client.authorization_status("rep_12:00", self.action.action_id, self.action.run_id, action_type="ISOLATE_BATTERY")
        self.assertEqual(status, "unauthorized_action")

        with patch("aegis.provenance.get_neo4j_client", return_value=client):
            prov = verify_provenance(self.action)

        self.assertFalse(prov.verified)
        self.assertEqual(prov.status, "unauthorized_action")

        pol = PolicyResult(decision="allow", matched_rule_id="rule_002_emergency", reason="Emergency ok")
        beh = BehaviourResult(flagged=False, score=0.0)
        risk = evaluate_risk(pol, prov, beh)
        decision = make_decision(self.action, pol, prov, beh, risk)

        self.assertEqual(decision.final_decision, "block")
        self.assertIn("Provenance Denied", decision.reason)

    def test_reused_report_id_is_blocked(self):
        """Vulnerability: Reusing a valid report ID for an unauthorized second action must be BLOCKED."""
        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        session = Mock()
        client.driver.session.return_value.__enter__.return_value = session
        session.run.return_value.single.return_value = {
            "report_exists": True,
            "report_exists_anywhere": True,
            "monitoring_link_exists": True,
            "response_link_exists": True,
            "action_exists": True,
            "claim_matches": True,
            "report_reused": True,
        }

        with patch("aegis.provenance.get_neo4j_client", return_value=client):
            prov = verify_provenance(self.action)

        self.assertFalse(prov.verified)
        self.assertEqual(prov.status, "report_reused")

        pol = PolicyResult(decision="allow", matched_rule_id="rule_002_emergency", reason="Emergency ok")
        beh = BehaviourResult(flagged=False, score=0.0)
        risk = evaluate_risk(pol, prov, beh)
        decision = make_decision(self.action, pol, prov, beh, risk)

        self.assertEqual(decision.final_decision, "block")
        self.assertIn("reuse", decision.reason.lower())

    def test_temporary_neo4j_failure_fails_closed_never_allows(self):
        """Invariant: If Neo4j is unavailable, AEGIS must fail closed and NEVER return ALLOW."""
        client = Mock()
        client.driver = None

        with patch("aegis.provenance.get_neo4j_client", return_value=client):
            prov = verify_provenance(self.action)

        self.assertFalse(prov.verified)
        self.assertEqual(prov.status, "unavailable")

        # Even if policy and behaviour are completely clean:
        pol = PolicyResult(decision="allow", matched_rule_id="test_rule", reason="Test allow")
        beh = BehaviourResult(flagged=False, score=0.0)
        risk = evaluate_risk(pol, prov, beh)
        decision = make_decision(self.action, pol, prov, beh, risk)

        self.assertNotEqual(decision.final_decision, "allow")
        self.assertIn(decision.final_decision, ("block", "human_approval"))


class FailClosedPolicyRegressionTest(unittest.TestCase):
    """P0 Regression tests: Policy engine fail-closed behavior."""

    def test_unknown_action_type_fails_closed_never_allows(self):
        """Vulnerability: Unrecognized actions must never default to ALLOW."""
        unknown_action = ProposedAction(
            action_id="act_unknown",
            run_id="run_test",
            action_type="MAINTAIN_STATUS",  # valid Pydantic literal
            target="none",
            reason="Unknown test",
            priority="HIGH",
            claimed_authorization="rep_test",
        )
        # Manually alter action_type to simulate unknown payload bypassing schema
        unknown_action.__dict__["action_type"] = "MALICIOUS_OVERRIDE_BREAKER"

        res = verify_policy(unknown_action)
        self.assertNotEqual(res.decision, "allow")
        self.assertIn(res.decision, ("block", "human_approval"))

    def test_battery_isolation_priority_bypass_blocked_when_telemetry_normal(self):
        """Vulnerability: Proposing HIGH priority battery isolation on healthy microgrid is BLOCKED."""
        action = ProposedAction(
            action_id="act_bypass",
            run_id="run_bypass",
            action_type="ISOLATE_BATTERY",
            target="battery_1",
            reason="Unsubstantiated priority escalation",
            priority="HIGH",
            claimed_authorization="rep_10:00",
        )
        context = {
            "battery_temperature_c": 36.5,
            "report_status": "NORMAL",
            "voltage_pu": 1.01,
        }

        res = verify_policy(action, context=context)
        self.assertEqual(res.decision, "block")
        self.assertEqual(res.matched_rule_id, "rule_002c")
        self.assertIn("battery temperature is normal", res.reason)

    def test_safe_action_type_with_forged_auth_is_blocked(self):
        """Vulnerability: Benign action types cannot bypass authorization verification if forged."""
        benign_action = ProposedAction(
            action_id="act_benign",
            run_id="run_test",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="Routine maintenance",
            priority="LOW",
            claimed_authorization="auth_tok_hacked_admin_999",
        )

        res = verify_policy(benign_action)
        self.assertEqual(res.decision, "block")
        self.assertEqual(res.matched_rule_id, "rule_000_forged_auth")

    def test_default_unmatched_severe_action_denied(self):
        """Vulnerability: An unmatched severe action without permissive rules must default to BLOCK."""
        # Empty ruleset forces default evaluation
        action = ProposedAction(
            action_id="act_custom",
            run_id="run_test",
            action_type="SHUTDOWN_LOAD",
            target="load_1",
            reason="Test unmatched",
            priority="HIGH",
            claimed_authorization="rep_10:00",
        )

        res = verify_policy(action, rules=[])
        self.assertEqual(res.decision, "block")
        self.assertEqual(res.matched_rule_id, "default_deny")


class LLMHallucinationSafetyTest(unittest.TestCase):
    """P0 Regression tests: LLM output cannot override physical safety rules."""

    def test_llm_anomaly_hallucination_rejected_on_healthy_telemetry(self):
        """Vulnerability: When actual physical telemetry is healthy, an LLM hallucination
        must NOT convert the final diagnosis to ANOMALY or trigger emergency isolation."""
        rule_status = "NORMAL"
        rule_severity = "NONE"
        rule_issues = []
        rule_evidence = {"voltage_pu": 1.01, "battery_temperature_c": 35.0}
        rule_action = None

        # LLM hallucinates an emergency anomaly on 35.0 C battery
        hallucinated_llm = {
            "status": "ANOMALY",
            "severity": "HIGH",
            "issue": "Critical battery temperature runaway detected at 95 C!",
            "evidence": {"battery_temperature_c": 95.0},
            "recommended_action": "Immediately isolate battery_1",
            "confidence": 0.95,
        }

        report = _merge_diagnoses(
            rule_status, rule_severity, rule_issues, rule_evidence, rule_action,
            hallucinated_llm, timestamp="12:00", run_id="run_hallucination_test"
        )

        # Invariant: Final diagnosis MUST remain NORMAL with severity NONE
        self.assertEqual(report.status, "NORMAL")
        self.assertEqual(report.severity, "NONE")
        self.assertIsNone(report.issue)

        # Invariant: The unverified hypothesis is preserved in evidence for human review
        self.assertIn("unverified_llm_hypothesis", report.evidence)
        hypothesis = report.evidence["unverified_llm_hypothesis"]
        self.assertEqual(hypothesis["status"], "ANOMALY")
        self.assertIn("Critical battery temperature", hypothesis["issue"])

        # Feed this report to Response Agent: must propose MAINTAIN_STATUS, NOT ISOLATE_BATTERY
        resp_input = ResponseInput(
            diagnostic_report=report,
            current_state={"battery_temperature_c": 35.0}
        )
        action = _deterministic_response(report)
        self.assertEqual(action.action_type, "MAINTAIN_STATUS")
        self.assertEqual(action.priority, "LOW")

    def test_response_agent_sanitizer_blocks_hallucinated_destructive_actions(self):
        """Vulnerability: If LLM proposes ISOLATE_BATTERY when report status is NORMAL,
        the Response Agent sanitization layer must override to deterministic baseline."""
        normal_report = MonitoringReport(
            run_id="run_test",
            report_id="rep_12:00",
            timestamp="12:00",
            status="NORMAL",
            severity="NONE",
            confidence=1.0,
        )
        baseline_action = _deterministic_response(normal_report)

        # LLM proposes destructive action
        hallucinated_action_dict = {
            "action_type": "ISOLATE_BATTERY",
            "target": "battery_1",
            "priority": "HIGH",
            "reason": "LLM hallucinations demand shutdown",
        }

        sanitized = _sanitize_action(hallucinated_action_dict, baseline_action, normal_report)
        self.assertEqual(sanitized.action_type, "MAINTAIN_STATUS")
        self.assertEqual(sanitized.target, "none")
        self.assertEqual(sanitized.priority, "LOW")

    def test_malformed_llm_data_handled_gracefully(self):
        """Schema validation: Non-dict or malformed LLM outputs fall back safely to deterministic rules."""
        report = _merge_diagnoses(
            rule_status="NORMAL", rule_severity="NONE", rule_issues=[],
            rule_evidence={}, rule_action=None,
            llm_data="MALFORMED_NON_DICT_STRING",  # type: ignore
            timestamp="12:00", run_id="run_test"
        )
        self.assertEqual(report.status, "NORMAL")
        self.assertEqual(report.severity, "NONE")


class ReplayProtectionRegressionTest(unittest.TestCase):
    """P1 Regression tests: Replay protection, session isolation, and regression detection."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_replay.db")
        init_db(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_duplicate_observation_is_flagged(self):
        """Duplicate observation within the same session must be flagged as a replay."""
        obs = {
            "timestamp": "10:00",
            "voltage_pu": 1.01,
            "load_kw": 25.0,
            "solar_kw": 10.0,
            "battery_soc_pct": 55.0,
            "battery_temperature_c": 32.0,
            "transformer_loading_pct": 18.0,
            "run_id": "run_1",
        }
        res1 = record_observation_with_replay_check(
            ObservationRow(**obs), session_id="sess_1", db_path=self.db_path
        )
        self.assertFalse(res1.detected)

        res2 = record_observation_with_replay_check(
            ObservationRow(**obs), session_id="sess_1", db_path=self.db_path
        )
        self.assertTrue(res2.detected)
        self.assertIn("Duplicate", res2.reason)

    def test_timestamp_regression_is_flagged(self):
        """Observation with an earlier timestamp than the latest accepted is flagged as replay."""
        obs1 = {
            "timestamp": "10:30",
            "voltage_pu": 1.01,
            "load_kw": 25.0,
            "solar_kw": 10.0,
            "battery_soc_pct": 55.0,
            "battery_temperature_c": 32.0,
            "transformer_loading_pct": 18.0,
            "run_id": "run_1",
        }
        record_observation_with_replay_check(
            ObservationRow(**obs1), session_id="sess_1", db_path=self.db_path
        )

        obs2 = dict(obs1, timestamp="10:15", run_id="run_2")
        res2 = record_observation_with_replay_check(
            ObservationRow(**obs2), session_id="sess_1", db_path=self.db_path
        )
        self.assertTrue(res2.detected)
        self.assertIn("predates", res2.reason)

    def test_session_rollover_prevents_false_positives(self):
        """Observations from previous sessions must NOT be falsely classified as replays in a new session."""
        obs = {
            "timestamp": "10:00",
            "voltage_pu": 1.01,
            "load_kw": 25.0,
            "solar_kw": 10.0,
            "battery_soc_pct": 55.0,
            "battery_temperature_c": 32.0,
            "transformer_loading_pct": 18.0,
            "run_id": "run_sess1",
        }
        # Recorded in session 1
        res1 = record_observation_with_replay_check(
            ObservationRow(**obs), session_id="session_alpha", db_path=self.db_path
        )
        self.assertFalse(res1.detected)

        # Same observation presented in session 2 must be legitimately accepted
        obs2 = dict(obs, run_id="run_sess2")
        res2 = record_observation_with_replay_check(
            ObservationRow(**obs2), session_id="session_beta", db_path=self.db_path
        )
        self.assertFalse(res2.detected)
        self.assertEqual(res2.session_id, "session_beta")

    def test_replayed_observation_excluded_from_trusted_baselines(self):
        """Replayed observations must not enter trusted historical baselines."""
        valid_obs = {
            "timestamp": "10:00",
            "voltage_pu": 1.01,
            "load_kw": 25.0,
            "solar_kw": 10.0,
            "battery_soc_pct": 55.0,
            "battery_temperature_c": 32.0,
            "transformer_loading_pct": 18.0,
            "run_id": "run_valid",
        }
        record_observation_with_replay_check(
            ObservationRow(**valid_obs), session_id="sess_1", db_path=self.db_path
        )

        # Submit a replay
        obs_replay = dict(valid_obs, run_id="run_replay")
        record_observation_with_replay_check(
            ObservationRow(**obs_replay), session_id="sess_1", db_path=self.db_path
        )

        history = query_recent_observations(10, db_path=self.db_path, session_id="sess_1")
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["run_id"], "run_valid")

    def test_decision_controller_hard_blocks_on_replay(self):
        """Invariant: An action resulting from a replayed observation must be BLOCKED by controller."""
        action = ProposedAction(
            action_id="act_replay",
            run_id="run_test",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="Routine maintenance",
            priority="LOW",
            claimed_authorization="rep_test",
        )
        pol = PolicyResult(decision="allow", matched_rule_id="rule_003", reason="Benign")
        prov = ProvenanceResult(verified=True, trace_length=3, status="verified", reason="Verified")
        beh = BehaviourResult(flagged=False, score=0.0)

        # Risk result with replay_detected=True
        replay_flag = ReplayCheckResult(
            detected=True,
            reason="Duplicate fingerprint detected",
            fingerprint="abc",
            observation_timestamp="10:00",
        )
        risk = evaluate_risk(pol, prov, beh, replay_result=replay_flag)
        self.assertTrue(risk.replay_detected)

        decision = make_decision(action, pol, prov, beh, risk)
        self.assertEqual(decision.final_decision, "block")
        self.assertIn("replay attack", decision.reason)


class PhaseB2ProvenanceHardeningRegressionTest(unittest.TestCase):
    """
    Phase B.2 Regression Tests:
    1. A rejected proposal cannot create trusted approved lineage (Fix V-01).
    2. Two concurrent requests cannot both consume the same report (Fix V-02).
    3. A report cannot authorize an action from another session (Fix V-03).
    4. A database failure during authorization consumption never results in ALLOW.
    """

    def setUp(self):
        reset_behaviour_history()
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_file.name
        self.temp_file.close()
        init_db(self.db_path)

    def tearDown(self):
        try:
            Path(self.db_path).unlink(missing_ok=True)
        except Exception:
            pass

    def test_rejected_proposal_cannot_create_trusted_approved_lineage(self):
        """Fix V-01: A rejected proposal must not create trusted approved lineage in the graph."""
        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        mock_session = Mock()
        client.driver.session.return_value.__enter__.return_value = mock_session

        obs = {"timestamp": "12:00", "run_id": "run_rej", "session_id": "sess_1"}
        rep = {"report_id": "rep_12:00", "run_id": "run_rej", "session_id": "sess_1", "status": "NORMAL", "severity": "NONE"}
        action = {
            "action_id": "act_rej_01",
            "run_id": "run_rej",
            "session_id": "sess_1",
            "action_type": "ISOLATE_BATTERY",
            "target": "battery_1",
            "claimed_authorization": "rep_12:00",
        }

        # 1. Proposal logging must mark action as PROPOSED without [:CONSUMED_BY]
        client.log_action_provenance(obs, rep, action, session_id="sess_1")
        proposal_query, proposal_params = mock_session.run.call_args.args[0], mock_session.run.call_args.args[1] if len(mock_session.run.call_args.args) > 1 else mock_session.run.call_args.kwargs
        self.assertIn("a.status = 'PROPOSED'", proposal_query)
        self.assertNotIn("MERGE (r)-[:CONSUMED_BY]->(a)", proposal_query)

        # 2. Rejection logging must set BLOCKED and must NOT establish CONSUMED_BY lineage
        decision_payload = {"final_decision": "block", "run_id": "run_rej"}
        client.log_aegis_decision(action["action_id"], "run_rej", decision_payload, session_id="sess_1")
        decision_query = mock_session.run.call_args.args[0]
        self.assertIn("SET a.status = $status_val", decision_query)
        self.assertEqual(mock_session.run.call_args.kwargs["status_val"], "BLOCKED")

        # 3. An unapproved proposal must not cause authorization_status to consider the report reused
        mock_session.run.return_value.single.return_value = {
            "report_exists": True,
            "monitoring_link_exists": True,
            "response_link_exists": True,
            "action_exists": True,
            "claim_matches": True,
            "report_reused": False,
            "report_status": "ANOMALY",
            "report_severity": "HIGH",
            "action_type": "ISOLATE_BATTERY",
            "report_session_id": "sess_1",
            "action_session_id": "sess_1",
        }
        status = client.authorization_status("rep_12:00", "act_new", "run_rej", session_id="sess_1")
        self.assertNotEqual(status, "report_reused")

    def test_concurrent_requests_cannot_both_consume_same_report(self):
        """Fix V-02: Two concurrent requests cannot both consume the same authorization report."""
        import concurrent.futures
        from database.sqlite import consume_report_authorization, is_report_consumed

        report_id = "rep_shared_atomic_001"
        session_id = "session_concurrency_test"
        num_workers = 10
        results = []

        def worker_claim(worker_id: int) -> bool:
            return consume_report_authorization(
                report_id=report_id,
                action_id=f"act_worker_{worker_id}",
                session_id=session_id,
                run_id=f"run_worker_{worker_id}",
                db_path=self.db_path,
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(worker_claim, i) for i in range(num_workers)]
            for f in concurrent.futures.as_completed(futures):
                results.append(f.result())

        # Invariant: Exactly ONE thread succeeds in consuming the report
        self.assertEqual(results.count(True), 1, "Exactly one worker must succeed in consuming the report")
        self.assertEqual(results.count(False), num_workers - 1, "All concurrent competitors must fail")
        self.assertTrue(is_report_consumed(report_id, session_id, db_path=self.db_path))

        # Scoped isolation: Another session CAN consume the report ID for its independent simulation
        diff_session_result = consume_report_authorization(
            report_id=report_id,
            action_id="act_other_session",
            session_id="session_different_boundary",
            run_id="run_diff",
            db_path=self.db_path,
        )
        self.assertTrue(diff_session_result, "Different session must be able to claim report under its own boundary")

    def test_report_cannot_authorize_action_from_another_session(self):
        """Fix V-03: A report from Session A cannot authorize an action in Session B even if run IDs collide."""
        action = ProposedAction(
            action_id="act_sess_b",
            run_id="run_colliding_123",
            session_id="session_beta",
            action_type="ISOLATE_BATTERY",
            target="battery_1",
            reason="Action proposed in session beta",
            priority="HIGH",
            claimed_authorization="rep_session_alpha_only",
        )

        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        mock_session = Mock()
        client.driver.session.return_value.__enter__.return_value = mock_session

        # Mock report belonging to session_alpha while action is in session_beta
        mock_session.run.return_value.single.return_value = {
            "report_exists": True,
            "monitoring_link_exists": True,
            "response_link_exists": True,
            "action_exists": True,
            "claim_matches": True,
            "report_status": "ANOMALY",
            "report_severity": "HIGH",
            "report_session_id": "session_alpha",
            "action_session_id": "session_beta",
            "action_type": "ISOLATE_BATTERY",
            "report_reused": False,
        }

        with patch("aegis.provenance.get_neo4j_client", return_value=client):
            res = verify_provenance(action)

        self.assertFalse(res.verified)
        self.assertEqual(res.status, "mismatched_session_id")
        self.assertIn("different simulation session", res.reason)

        pol = verify_policy(action)
        beh = analyze_behaviour(action)
        risk = evaluate_risk(pol, res, beh)
        decision = make_decision(action, pol, res, beh, risk)
        self.assertNotEqual(decision.final_decision, "allow", "Cross-session authorized action must NEVER be ALLOW")

    def test_database_failure_during_authorization_consumption_never_results_in_allow(self):
        """Fix V-02 / Requirement 4: Database failure during consumption fails closed and never returns ALLOW."""
        from workflow.graph import decision_controller_node, AttackContext

        action = ProposedAction(
            action_id="act_db_fail_test",
            run_id="run_db_fail",
            session_id="sess_fail_test",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="Routine maintain",
            priority="LOW",
            claimed_authorization="rep_legit_100",
        )
        pol = PolicyResult(decision="allow", matched_rule_id="rule_003", reason="Allowed normal")
        prov = ProvenanceResult(verified=True, trace_length=3, status="verified", reason="Verified")
        beh = BehaviourResult(flagged=False, score=0.0)
        risk = evaluate_risk(pol, prov, beh)

        state = {
            "proposed_action": action,
            "policy_result": pol,
            "provenance_result": prov,
            "behaviour_result": beh,
            "risk_result": risk,
            "observation": {"timestamp": "10:00", "session_id": "sess_fail_test"},
            "run_id": "run_db_fail",
            "session_id": "sess_fail_test",
            "attack_context": AttackContext(is_injected_attack=False, attack_type=None),
        }

        # Simulate SQLite failure during consumption (e.g. database locked or disk error)
        with (
            patch("workflow.graph.persist_decision_and_consume_report"),
            patch("database.sqlite.consume_report_authorization", side_effect=sqlite3.OperationalError("database is locked")),
        ):
            output = decision_controller_node(state)

        result_decision = output["workflow_result"].aegis_result
        self.assertEqual(result_decision.final_decision, "block", "Database failure during consumption must fail closed to BLOCK")
        self.assertIn("fail-closed", result_decision.reason.lower())


class PhaseB3HardeningRegressionTest(unittest.TestCase):
    """
    Phase B.3 Regression Tests: Decision Durability and Provenance Integrity.
    Covers:
    1. Atomic SQLite decision persistence with rollback on insertion failure.
    2. Concurrent authorization consumption guaranteeing at most one claim.
    3. SQLite to Neo4j outbox retry, idempotency, and non-mutation of blocked decisions.
    4. Canonical action content digest binding and tamper resistance (parameters, target, action_type).
    """

    def setUp(self):
        reset_behaviour_history()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_b3.db")
        init_db(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_decision_insertion_failure_rolls_back_report_consumption_atomically(self):
        """
        Requirement 1: If the decision cannot be persisted, the report MUST NOT remain consumed.
        Transaction must atomically roll back so the report is not orphaned as CONSUMED.
        """
        report_id = "rep_atomic_test_001"
        session_id = "session_atomic_01"
        run_id = "run_atomic_01"

        row = AEGISDecisionRow(
            run_id=run_id,
            session_id=session_id,
            timestamp="10:00",
            action_id="act_atomic_01",
            policy_result='{"decision": "allow"}',
            provenance_result='{"verified": true}',
            behaviour_flag=0,
            risk_score=0.1,
            final_decision="allow",
            reason="Approved action",
            is_injected_attack=0,
            attack_type=None,
        )

        # Drop the aegis_decisions table to force a decision-insertion failure inside the transaction
        conn = sqlite3.connect(self.db_path)
        conn.execute("DROP TABLE aegis_decisions")
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError):
            persist_decision_and_consume_report(
                decision_row=row,
                report_id=report_id,
                action_digest="digest_test",
                db_path=self.db_path,
            )

        # Invariant: Report must NOT remain consumed after rollback
        self.assertFalse(
            is_report_consumed(report_id, session_id, db_path=self.db_path),
            "Report must not remain consumed when decision insertion fails (atomicity rollback guarantee)",
        )

        # Re-create schema to verify that clean insertion succeeds
        init_db(self.db_path)
        success, decision_id = persist_decision_and_consume_report(
            decision_row=row,
            report_id=report_id,
            action_digest="digest_test",
            db_path=self.db_path,
        )
        self.assertTrue(success)
        self.assertIsNotNone(decision_id)
        self.assertTrue(
            is_report_consumed(report_id, session_id, db_path=self.db_path),
            "Report must be marked consumed upon successful atomic decision persistence",
        )

    def test_concurrent_requests_result_in_at_most_one_successful_consumption(self):
        """
        Requirement 1: Concurrent requests in the same session must result in at most
        one successful authorization consumption.
        """
        import concurrent.futures

        report_id = "rep_race_b3"
        session_id = "session_race_b3"
        num_workers = 8

        def worker_attempt(worker_idx):
            row = AEGISDecisionRow(
                run_id=f"run_worker_{worker_idx}",
                session_id=session_id,
                timestamp="10:00",
                action_id=f"act_worker_{worker_idx}",
                policy_result='{"decision": "allow"}',
                provenance_result='{"verified": true}',
                behaviour_flag=0,
                risk_score=0.1,
                final_decision="allow",
                reason="Race worker",
                is_injected_attack=0,
                attack_type=None,
            )
            success, _ = persist_decision_and_consume_report(
                decision_row=row,
                report_id=report_id,
                action_digest="test_digest",
                db_path=self.db_path,
            )
            return success

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(worker_attempt, i) for i in range(num_workers)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        self.assertEqual(results.count(True), 1, "Exactly one concurrent worker must succeed in consuming the report")
        self.assertEqual(results.count(False), num_workers - 1, "All competitor workers must be rejected")
        self.assertTrue(is_report_consumed(report_id, session_id, db_path=self.db_path))

    def test_neo4j_outbox_retryable_and_never_mutates_blocked_decision(self):
        """
        Requirement 2: Failed Neo4j audit writes are stored in the outbox,
        retryable, idempotent, and NEVER change a blocked decision to approved.
        """
        report_id = "rep_outbox_test"
        session_id = "session_outbox_01"
        run_id = "run_outbox_01"

        blocked_decision = FinalDecision(
            action=ProposedAction(
                action_id="act_blocked_01",
                run_id=run_id,
                session_id=session_id,
                action_type="ISOLATE_BATTERY",
                target="battery_1",
                reason="High risk detected",
                priority="HIGH",
                claimed_authorization=report_id,
            ),
            policy_result=PolicyResult(stage="policy", decision="block", matched_rule_id="rule_001", reason="Blocked"),
            provenance_result=ProvenanceResult(verified=False, trace_length=0, status="unauthorized", reason="Blocked"),
            behaviour_result=BehaviourResult(flagged=True, score=0.8),
            risk_result=RiskResult(score=0.9, band="HIGH", contributing_factors={}),
            final_decision="block",
            reason="Blocked by AEGIS security policy",
            run_id=run_id,
        )

        row = AEGISDecisionRow(
            run_id=run_id,
            session_id=session_id,
            timestamp="10:00",
            action_id="act_blocked_01",
            policy_result=blocked_decision.policy_result.model_dump_json(),
            provenance_result=blocked_decision.provenance_result.model_dump_json(),
            behaviour_flag=1,
            risk_score=0.9,
            final_decision="block",
            reason=blocked_decision.reason,
            is_injected_attack=1,
            attack_type="malicious_isolation",
        )

        outbox_payload = {
            "aegis_decision": blocked_decision.model_dump(),
            "action_digest": "digest_blocked",
        }

        # 1. Persist decision + outbox event in the same transaction
        success, decision_id = persist_decision_and_consume_report(
            decision_row=row,
            report_id=None,
            action_digest="digest_blocked",
            outbox_payload=outbox_payload,
            db_path=self.db_path,
        )
        self.assertTrue(success)

        # Check outbox status is PENDING initially
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT status, retry_count FROM neo4j_outbox WHERE action_id = 'act_blocked_01'")
        outbox_rec = cur.fetchone()
        conn.close()
        self.assertEqual(outbox_rec[0], "PENDING")
        self.assertEqual(outbox_rec[1], 0)

        # 2. Simulate failed Neo4j push: outbox status becomes FAILED with retry_count incremented
        failing_client = Mock()
        failing_client.driver = Mock()
        failing_client.log_aegis_decision.side_effect = ConnectionError("Neo4j database down")

        synced = sync_neo4j_outbox(db_path=self.db_path, neo4j_client=failing_client)
        self.assertEqual(synced, 0)

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT status, retry_count, last_error FROM neo4j_outbox WHERE action_id = 'act_blocked_01'")
        failed_rec = cur.fetchone()
        conn.close()
        self.assertEqual(failed_rec[0], "FAILED")
        self.assertEqual(failed_rec[1], 1)
        self.assertIn("Neo4j database down", failed_rec[2])

        # 3. Simulate recovery: retry succeeds and updates status to SENT
        working_client = Mock()
        working_client.driver = Mock()

        synced = sync_neo4j_outbox(db_path=self.db_path, neo4j_client=working_client)
        self.assertEqual(synced, 1)

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT status, last_error FROM neo4j_outbox WHERE action_id = 'act_blocked_01'")
        sent_rec = cur.fetchone()
        cur.execute("SELECT final_decision FROM aegis_decisions WHERE action_id = 'act_blocked_01'")
        decision_rec = cur.fetchone()
        conn.close()

        self.assertEqual(sent_rec[0], "SENT")
        self.assertIsNone(sent_rec[1])
        # Invariant: Sync success must NEVER convert a blocked decision to approved
        self.assertEqual(decision_rec[0], "block", "Sync success must NEVER mutate a blocked decision")

    def test_outbox_delivery_confirmation_exception_handling(self):
        """
        Regression Test: Delivery confirmation when Neo4j raises an exception.
        - Neo4jClient.log_aegis_decision raises when driver session fails.
        - sync_neo4j_outbox captures error, preserves event as FAILED with error message,
          and does not mark SENT.
        """
        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        mock_session = Mock()
        mock_session.run.side_effect = ConnectionError("Neo4j cluster unavailable")
        client.driver.session.return_value.__enter__.return_value = mock_session

        decision_payload = {"final_decision": "block", "run_id": "run_exc_01"}
        with self.assertRaises(ConnectionError):
            client.log_aegis_decision(
                action_id="act_exc_01",
                run_id="run_exc_01",
                aegis_decision=decision_payload,
            )

        row = AEGISDecisionRow(
            run_id="run_exc_01",
            session_id="sess_exc",
            timestamp="10:00",
            action_id="act_exc_01",
            policy_result="{}",
            provenance_result="{}",
            behaviour_flag=0,
            risk_score=0.1,
            final_decision="block",
            reason="Test block",
            is_injected_attack=0,
            attack_type="none",
        )
        persist_decision_and_consume_report(
            decision_row=row,
            report_id=None,
            action_digest="digest_exc",
            outbox_payload={"aegis_decision": decision_payload, "action_digest": "digest_exc"},
            db_path=self.db_path,
        )

        synced = sync_neo4j_outbox(db_path=self.db_path, neo4j_client=client)
        self.assertEqual(synced, 0)

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT status, retry_count, last_error FROM neo4j_outbox WHERE action_id = 'act_exc_01'")
        rec = cur.fetchone()
        conn.close()
        self.assertEqual(rec[0], "FAILED")
        self.assertEqual(rec[1], 1)
        self.assertIn("Neo4j cluster unavailable", rec[2])

    def test_outbox_missing_action_node_detection_and_retryability(self):
        """
        Regression Test: Delivery confirmation when Neo4j returns without creating
        a decision because the required Action node is missing.
        - Neo4jClient.log_aegis_decision returns False (not True).
        - sync_neo4j_outbox does not mark SENT, records failure, and preserves retryability.
        """
        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        mock_session = Mock()
        mock_result = Mock()
        mock_result.single.return_value = {"decision_count": 0}
        mock_session.run.return_value = mock_result
        client.driver.session.return_value.__enter__.return_value = mock_session

        decision_payload = {"final_decision": "allow", "run_id": "run_missing_01"}
        success = client.log_aegis_decision(
            action_id="act_missing_01",
            run_id="run_missing_01",
            aegis_decision=decision_payload,
        )
        self.assertFalse(success, "Missing Action node must result in log_aegis_decision returning False")

        row = AEGISDecisionRow(
            run_id="run_missing_01",
            session_id="sess_missing",
            timestamp="10:00",
            action_id="act_missing_01",
            policy_result="{}",
            provenance_result="{}",
            behaviour_flag=0,
            risk_score=0.1,
            final_decision="allow",
            reason="Test allow",
            is_injected_attack=0,
            attack_type="none",
        )
        persist_decision_and_consume_report(
            decision_row=row,
            report_id=None,
            action_digest="digest_missing",
            outbox_payload={"aegis_decision": decision_payload, "action_digest": "digest_missing"},
            db_path=self.db_path,
        )

        synced = sync_neo4j_outbox(db_path=self.db_path, neo4j_client=client)
        self.assertEqual(synced, 0, "No events should be reported synced when Action node is missing")

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT status, retry_count, last_error FROM neo4j_outbox WHERE action_id = 'act_missing_01'")
        rec = cur.fetchone()
        conn.close()
        self.assertEqual(rec[0], "FAILED")
        self.assertEqual(rec[1], 1)
        self.assertIn("Action node not found", rec[2])

    def test_outbox_successful_write_marked_sent(self):
        """
        Regression Test: Successful Neo4j write followed by SENT marking.
        - Neo4jClient.log_aegis_decision returns True when decision_count == 1.
        - sync_neo4j_outbox updates status to SENT and clears last_error.
        """
        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        mock_session = Mock()
        mock_result = Mock()
        mock_result.single.return_value = {"decision_count": 1}
        mock_session.run.return_value = mock_result
        client.driver.session.return_value.__enter__.return_value = mock_session

        decision_payload = {"final_decision": "allow", "run_id": "run_success_01"}
        success = client.log_aegis_decision(
            action_id="act_success_01",
            run_id="run_success_01",
            aegis_decision=decision_payload,
        )
        self.assertTrue(success, "Verified decision creation must return True")

        row = AEGISDecisionRow(
            run_id="run_success_01",
            session_id="sess_success",
            timestamp="10:00",
            action_id="act_success_01",
            policy_result="{}",
            provenance_result="{}",
            behaviour_flag=0,
            risk_score=0.1,
            final_decision="allow",
            reason="Test allow",
            is_injected_attack=0,
            attack_type="none",
        )
        persist_decision_and_consume_report(
            decision_row=row,
            report_id=None,
            action_digest="digest_success",
            outbox_payload={"aegis_decision": decision_payload, "action_digest": "digest_success"},
            db_path=self.db_path,
        )

        synced = sync_neo4j_outbox(db_path=self.db_path, neo4j_client=client)
        self.assertEqual(synced, 1)

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT status, retry_count, last_error FROM neo4j_outbox WHERE action_id = 'act_success_01'")
        rec = cur.fetchone()
        conn.close()
        self.assertEqual(rec[0], "SENT")
        self.assertEqual(rec[1], 0)
        self.assertIsNone(rec[2])

    def test_canonical_digest_deterministic_serialization(self):
        """
        Requirement 3: Deterministic canonical SHA-256 digest computation
        regardless of dictionary key order or nested whitespace.
        """
        params_a = {"voltage_pu": 0.95, "nested": {"b": 2, "a": 1}, "list": [1, 2, 3]}
        params_b = {"nested": {"a": 1, "b": 2}, "list": [1, 2, 3], "voltage_pu": 0.95}

        digest_a = compute_action_digest("ISOLATE_BATTERY", "battery_1", params_a)
        digest_b = compute_action_digest("ISOLATE_BATTERY", "battery_1", params_b)

        self.assertEqual(digest_a, digest_b, "Equivalent parameter dicts must produce identical canonical digests")
        self.assertEqual(len(digest_a), 64, "Digest must be a 64-character SHA-256 hex string")

    def test_parameter_tampering_rejected_fail_closed(self):
        """
        Requirement 3: Modifying action parameters invalidates the digest and fails closed to BLOCK.
        """
        action = ProposedAction(
            action_id="act_tamper_param",
            run_id="run_param_01",
            session_id="session_param_01",
            action_type="ISOLATE_BATTERY",
            target="battery_1",
            reason="Safe test action",
            priority="HIGH",
            claimed_authorization="rep_valid_01",
            parameters={"limit_kw": 50},
        )
        self.assertTrue(action.is_digest_valid())

        # Adversary mutates parameter payload
        action.parameters["limit_kw"] = 500
        self.assertFalse(action.is_digest_valid())

        prov = verify_provenance(action)
        self.assertFalse(prov.verified)
        self.assertEqual(prov.status, "action_digest_mismatch")

        pol = verify_policy(action)
        beh = analyze_behaviour(action)
        risk = evaluate_risk(pol, prov, beh)
        decision = make_decision(action, pol, prov, beh, risk)
        self.assertEqual(decision.final_decision, "block")
        self.assertIn("action digest does not match", decision.reason.lower())

    def test_target_tampering_rejected_fail_closed(self):
        """
        Requirement 3: Modifying target component invalidates the digest and fails closed to BLOCK.
        """
        action = ProposedAction(
            action_id="act_tamper_target",
            run_id="run_target_01",
            session_id="session_target_01",
            action_type="ISOLATE_BATTERY",
            target="battery_1",
            reason="Safe test action",
            priority="HIGH",
            claimed_authorization="rep_valid_02",
        )
        self.assertTrue(action.is_digest_valid())

        # Adversary switches target from battery_1 to critical_load
        action.target = "critical_load"
        self.assertFalse(action.is_digest_valid())

        prov = verify_provenance(action)
        self.assertFalse(prov.verified)
        self.assertEqual(prov.status, "action_digest_mismatch")

        pol = verify_policy(action)
        beh = analyze_behaviour(action)
        risk = evaluate_risk(pol, prov, beh)
        decision = make_decision(action, pol, prov, beh, risk)
        self.assertEqual(decision.final_decision, "block")

    def test_action_type_tampering_rejected_fail_closed(self):
        """
        Requirement 3: Modifying action_type invalidates the digest and fails closed to BLOCK.
        """
        action = ProposedAction(
            action_id="act_tamper_type",
            run_id="run_type_01",
            session_id="session_type_01",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="Routine maintenance",
            priority="LOW",
            claimed_authorization="rep_valid_03",
        )
        self.assertTrue(action.is_digest_valid())

        # Adversary escalates action_type from MAINTAIN_STATUS to SHUTDOWN_LOAD
        action.action_type = "SHUTDOWN_LOAD"
        self.assertFalse(action.is_digest_valid())

        prov = verify_provenance(action)
        self.assertFalse(prov.verified)
        self.assertEqual(prov.status, "action_digest_mismatch")

        pol = verify_policy(action)
        beh = analyze_behaviour(action)
        risk = evaluate_risk(pol, prov, beh)
        decision = make_decision(action, pol, prov, beh, risk)
        self.assertEqual(decision.final_decision, "block")


if __name__ == "__main__":
    unittest.main()


