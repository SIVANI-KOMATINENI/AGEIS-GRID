"""Deterministic normal-path test for workflow component handoffs."""

from contextlib import redirect_stdout
from datetime import datetime
from io import StringIO
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import main
import workflow.graph as graph
import database.sqlite as sqlite_db
from agents.schemas import MonitoringReport, ProposedAction
from agents.response_agent import _fallback_rule_based_response
from agents.monitoring_agent import _fallback_rule_based_diagnosis
from aegis.behaviour import BehaviourResult, reset_behaviour_history
from aegis.controller import FinalDecision
from aegis.policy import PolicyResult
from aegis.provenance import ProvenanceResult
from aegis.risk import RiskResult


class WorkflowNormalPathTest(unittest.TestCase):
    def test_monitoring_fallback_preserves_run_id(self):
        report = _fallback_rule_based_diagnosis(
            graph.MonitoringInput(
                current={
                    "timestamp": "10:00",
                    "run_id": "run_monitoring_fallback",
                    "battery_temperature_c": 30.0,
                },
                recent_history=[],
                context={},
            )
        )

        self.assertEqual(report.run_id, "run_monitoring_fallback")

    def test_response_agent_claims_exact_report_id(self):
        report = MonitoringReport(
            run_id="run_report_fixture",
            report_id="rep_current_run_42",
            timestamp="18:51",
            status="ANOMALY",
            severity="MEDIUM",
            issue="Battery temperature is elevated.",
            confidence=0.95,
        )
        action = _fallback_rule_based_response(
            graph.ResponseInput(
                diagnostic_report=report,
                current_state={"battery_temperature_c": 40.4},
            )
        )

        self.assertEqual(action.claimed_authorization, report.report_id)
        self.assertEqual(action.run_id, report.run_id)
        self.assertNotEqual(action.claimed_authorization, "rep_18:51")

    def test_normal_observation_flows_through_agents_and_aegis(self):
        with patch.object(main, "datetime") as clock:
            clock.now.return_value = datetime(2024, 1, 1, 10, 0)
            observation, _, _ = main.create_current_observation()
        report = MonitoringReport(
            run_id="run_fixture",
            report_id="rep_10:00",
            timestamp="10:00",
            status="NORMAL",
            severity="NONE",
            issue=None,
            evidence={"battery_temperature_c": 30.0},
            recommended_action="Maintain normal operations.",
            confidence=1.0,
        )
        action = ProposedAction(
            action_id="act_10:00",
            run_id="run_fixture",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="System operating normally.",
            priority="LOW",
            claimed_authorization=report.report_id,
        )
        neo4j_client = Mock()
        event_order = []
        neo4j_client.log_action_provenance.side_effect = (
            lambda **kwargs: event_order.append("provenance_write")
        )
        neo4j_client.log_aegis_decision.side_effect = (
            lambda **kwargs: event_order.append("decision_write")
        )
        real_verify_policy = graph.verify_policy
        real_analyze_behaviour = graph.analyze_behaviour
        real_evaluate_risk = graph.evaluate_risk
        real_make_decision = graph.make_decision
        reset_behaviour_history()

        with (
            patch.object(
                graph,
                "run_monitoring_agent",
                side_effect=lambda inputs: report.model_copy(
                    update={"run_id": inputs.current["run_id"]}
                ),
            ) as monitor,
            patch.object(
                graph,
                "run_response_agent",
                side_effect=lambda inputs: action.model_copy(
                    update={"run_id": inputs.diagnostic_report.run_id}
                ),
            ) as response,
            patch.object(graph, "verify_policy", wraps=real_verify_policy) as policy,
            patch.object(
                graph,
                "verify_provenance",
                return_value=ProvenanceResult(
                    verified=True,
                    trace_length=0,
                    reason="Mocked provenance dependency.",
                ),
            ) as provenance,
            patch.object(
                graph,
                "analyze_behaviour",
                wraps=real_analyze_behaviour,
            ) as behaviour,
            patch.object(graph, "evaluate_risk", wraps=real_evaluate_risk) as risk,
            patch.object(graph, "make_decision", wraps=real_make_decision) as decision,
            patch.object(graph, "query_recent_observations", return_value=[]),
            patch.object(
                graph,
                "record_observation_with_replay_check",
                side_effect=lambda observation: graph.ReplayCheckResult(
                    detected=False,
                    reason="Fresh test observation.",
                    fingerprint=sqlite_db.observation_fingerprint(
                        observation.model_dump()
                    ),
                    observation_timestamp=observation.timestamp,
                    run_id=observation.run_id,
                ),
            ),
            patch.object(graph, "insert_agent_message"),
            patch.object(graph, "insert_attack_event") as insert_attack,
            patch.object(graph, "insert_aegis_decision"),
            patch.object(graph, "get_neo4j_client", return_value=neo4j_client),
        ):
            policy.side_effect = lambda proposed: (
                event_order.append("policy"),
                real_verify_policy(proposed),
            )[1]
            provenance.side_effect = lambda proposed: (
                event_order.append("provenance_verification"),
                ProvenanceResult(
                    verified=True,
                    trace_length=3,
                    reason="Mocked complete action provenance.",
                ),
            )[1]
            decision.side_effect = lambda *args: (
                event_order.append("decision_controller"),
                real_make_decision(*args),
            )[1]
            final_state = graph.build_workflow().invoke({"observation": observation})

        result = final_state["workflow_result"]
        monitoring_input = monitor.call_args.args[0]

        run_id = final_state["run_id"]
        self.assertEqual(
            {key: value for key, value in monitoring_input.current.items() if key != "run_id"},
            observation,
        )
        self.assertEqual(final_state["observation"]["run_id"], run_id)
        self.assertFalse(final_state["attack_context"].is_injected_attack)
        report = final_state["diagnostic_report"]
        action = final_state["proposed_action"]
        self.assertIs(response.call_args.args[0].diagnostic_report, report)
        self.assertEqual(report.run_id, run_id)
        self.assertEqual(action.run_id, run_id)
        self.assertEqual(result.aegis_result.run_id, run_id)
        self.assertIs(policy.call_args.args[0], action)
        self.assertIs(provenance.call_args.args[0], action)
        self.assertIs(behaviour.call_args.args[0], action)
        self.assertIs(result.proposed_action, action)
        self.assertIsInstance(result.aegis_result, FinalDecision)
        self.assertEqual(result.aegis_result.policy_result.decision, "allow")
        self.assertEqual(result.aegis_result.risk_result.band, "LOW")
        self.assertEqual(result.final_decision, "allow")
        self.assertIs(risk.call_args.args[0], result.aegis_result.policy_result)
        self.assertIs(decision.call_args.args[0], action)
        insert_attack.assert_not_called()
        neo4j_client.log_action_provenance.assert_called_once()
        neo4j_client.log_aegis_decision.assert_called_once()
        provenance_write = neo4j_client.log_action_provenance.call_args.kwargs
        self.assertEqual(provenance_write["observation"]["run_id"], run_id)
        self.assertEqual(provenance_write["report"]["run_id"], run_id)
        self.assertEqual(provenance_write["proposed_action"]["run_id"], run_id)
        self.assertEqual(neo4j_client.log_aegis_decision.call_args.kwargs["run_id"], run_id)
        self.assertLess(event_order.index("provenance_write"), event_order.index("policy"))
        self.assertLess(event_order.index("policy"), event_order.index("provenance_verification"))
        self.assertLess(event_order.index("provenance_verification"), event_order.index("decision_controller"))
        self.assertLess(event_order.index("decision_controller"), event_order.index("decision_write"))

    def test_main_displays_actual_result_fields(self):
        action = ProposedAction(
            action_id="act_10:00",
            run_id="run_main_display",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="System operating normally.",
            priority="LOW",
        )
        decision = FinalDecision(
            final_decision="allow",
            reason="Action approved.",
            action=action,
            policy_result=PolicyResult(decision="allow", reason="Policy passed."),
            provenance_result=ProvenanceResult(
                verified=True,
                trace_length=0,
                reason="Provenance passed.",
            ),
            behaviour_result=BehaviourResult(flagged=False),
            risk_result=RiskResult(
                score=0.0,
                band="LOW",
                contributing_factors={
                    "policy": 0.0,
                    "provenance": 0.0,
                    "behaviour": 0.0,
                },
            ),
        )
        report = MonitoringReport(
            run_id="run_main_display",
            report_id="rep_10:00",
            timestamp="10:00",
            status="NORMAL",
            severity="NONE",
            confidence=1.0,
        )
        workflow = Mock()
        workflow.invoke.return_value = {
            "workflow_result": graph.WorkflowResult(aegis_result=decision),
            "attack_context": graph.AttackContext(),
            "diagnostic_report": report,
        }
        output = StringIO()

        with (
            patch.object(main, "get_scenario", return_value="normal"),
            patch.object(main, "init_db"),
            patch.object(
                main,
                "create_current_observation",
                return_value=(
                    {
                        "timestamp": "10:00",
                        "voltage_pu": 1.0,
                        "load_kw": 40.0,
                        "solar_kw": 10.0,
                        "battery_soc_pct": 55.0,
                        "battery_temperature_c": 30.0,
                        "transformer_loading_pct": 15.0,
                    },
                    datetime(2024, 1, 1, 10),
                    600,
                ),
            ),
            patch.object(main, "build_workflow", return_value=workflow),
            redirect_stdout(output),
        ):
            main.main()

        self.assertIn("Decision : allow", output.getvalue())
        self.assertIn("Flagged : False", output.getvalue())
        self.assertIn("Band : LOW", output.getvalue())
        self.assertIn(">>> ALLOW", output.getvalue())

    def test_detected_replay_cannot_result_in_allow_decision(self):
        action = ProposedAction(
            action_id="act_replay_gate",
            sender_agent="response_agent",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="Benign action on replayed telemetry.",
            priority="LOW",
        )
        policy_res = PolicyResult(decision="allow", reason="Policy passed.")
        prov_res = ProvenanceResult(verified=True, trace_length=3, reason="Verified.")
        behav_res = BehaviourResult(flagged=False, score=0.0)

        # Simulating detected replay
        replay_res = graph.ReplayCheckResult(
            detected=True,
            reason="Replay detected in observation stream.",
            fingerprint="fake_fingerprint",
            observation_timestamp="10:00",
        )
        risk_res = graph.evaluate_risk(policy_res, prov_res, behav_res, replay_result=replay_res)
        self.assertTrue(risk_res.replay_detected)
        self.assertEqual(risk_res.score, 1.0)
        self.assertEqual(risk_res.band, "HIGH")

        decision = graph.make_decision(action, policy_res, prov_res, behav_res, risk_res)
        self.assertEqual(decision.final_decision, "block")
        self.assertIn("replay", decision.reason.lower())


class WorkflowSQLiteIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "audit.db")
        sqlite_db.init_db(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def run_workflow_with_persistence(self, timestamp):
        hour, minute = (int(part) for part in timestamp.split(":"))
        with patch.object(main, "datetime") as clock:
            clock.now.return_value = datetime(2024, 1, 1, hour, minute)
            observation, _, _ = main.create_current_observation()

        report = MonitoringReport(
            run_id="run_fixture",
            report_id=f"rep_{timestamp}",
            timestamp=timestamp,
            status="NORMAL",
            severity="NONE",
            evidence={"battery_temperature_c": observation["battery_temperature_c"]},
            confidence=1.0,
        )
        action = ProposedAction(
            action_id=f"act_{timestamp}",
            run_id="run_fixture",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="Deterministic integration-test action.",
            priority="LOW",
            claimed_authorization=report.report_id,
        )
        neo4j_client = Mock()

        with (
            patch.object(
                graph,
                "run_monitoring_agent",
                side_effect=lambda inputs: report.model_copy(update={
                    "run_id": inputs.current["run_id"],
                    "timestamp": inputs.current["timestamp"],
                    "report_id": f"rep_{inputs.current['timestamp']}",
                    "evidence": {
                        "battery_temperature_c": inputs.current.get(
                            "battery_temperature_c"
                        )
                    },
                    "status": (
                        "ANOMALY"
                        if inputs.current.get("battery_temperature_c", 30.0) > 60.0
                        else "NORMAL"
                    ),
                    "severity": (
                        "HIGH"
                        if inputs.current.get("battery_temperature_c", 30.0) > 60.0
                        else "NONE"
                    ),
                }),
            ) as monitor,
            patch.object(
                graph,
                "run_response_agent",
                side_effect=lambda inputs: action.model_copy(update={
                    "run_id": inputs.diagnostic_report.run_id,
                    "action_id": f"act_{inputs.diagnostic_report.timestamp}",
                    "claimed_authorization": inputs.diagnostic_report.report_id,
                    "action_type": (
                        "ISOLATE_BATTERY"
                        if inputs.diagnostic_report.status == "ANOMALY"
                        else "MAINTAIN_STATUS"
                    ),
                    "target": (
                        "battery_1"
                        if inputs.diagnostic_report.status == "ANOMALY"
                        else "none"
                    ),
                    "priority": (
                        "HIGH"
                        if inputs.diagnostic_report.status == "ANOMALY"
                        else "LOW"
                    ),
                }),
            ),
            patch.object(graph, "verify_provenance", return_value=ProvenanceResult(
                verified=True,
                trace_length=0,
                reason="Provenance mocked for SQLite test.",
            )),
            patch.object(
                graph,
                "query_recent_observations",
                side_effect=lambda count: sqlite_db.query_recent_observations(
                    count,
                    db_path=self.db_path,
                ),
            ),
            patch.object(
                graph,
                "record_observation_with_replay_check",
                side_effect=lambda row: sqlite_db.record_observation_with_replay_check(
                    row,
                    db_path=self.db_path,
                ),
            ),
            patch.object(
                graph,
                "insert_agent_message",
                side_effect=lambda row: sqlite_db.insert_agent_message(
                    row,
                    db_path=self.db_path,
                ),
            ),
            patch.object(
                graph,
                "insert_attack_event",
                side_effect=lambda row: sqlite_db.insert_attack_event(
                    row,
                    db_path=self.db_path,
                ),
            ),
            patch.object(
                graph,
                "insert_aegis_decision",
                side_effect=lambda row: sqlite_db.insert_aegis_decision(
                    row,
                    db_path=self.db_path,
                ),
            ),
            patch.object(
                graph,
                "persist_decision_and_consume_report",
                side_effect=lambda decision_row, report_id=None, action_digest=None, outbox_payload=None: sqlite_db.persist_decision_and_consume_report(
                    decision_row=decision_row,
                    report_id=report_id,
                    action_digest=action_digest,
                    outbox_payload=outbox_payload,
                    db_path=self.db_path,
                ),
            ),
            patch.object(
                graph,
                "sync_neo4j_outbox",
                side_effect=lambda neo4j_client=None, limit=50: sqlite_db.sync_neo4j_outbox(
                    db_path=self.db_path,
                    neo4j_client=neo4j_client,
                    limit=limit,
                ),
            ),
            patch.object(graph, "get_neo4j_client", return_value=neo4j_client),
        ):
            state = graph.build_workflow().invoke({"observation": observation})

        return state, monitor

    def assert_one_completed_audit_record(self, state, expected_attack):
        observation = sqlite_db.query_recent_observations(5, self.db_path)
        messages = sqlite_db.query_recent_agent_messages(5, self.db_path)
        attacks = sqlite_db.query_recent_attack_events(5, self.db_path)
        decisions = sqlite_db.query_recent_decisions(5, self.db_path)

        self.assertEqual(len(observation), 1)
        self.assertEqual(len(messages), 2)
        self.assertEqual(len(attacks), int(expected_attack is not None))
        self.assertEqual(len(decisions), 1)
        run_id = state["run_id"]
        self.assertEqual(observation[0]["run_id"], run_id)
        self.assertEqual({message["run_id"] for message in messages}, {run_id})
        self.assertEqual(decisions[0]["run_id"], run_id)
        self.assertEqual(state["diagnostic_report"].run_id, run_id)
        self.assertEqual(state["proposed_action"].run_id, run_id)
        self.assertEqual(state["workflow_result"].aegis_result.run_id, run_id)
        self.assertEqual(
            [message["receiver_agent"] for message in messages],
            ["response_agent", "aegis_grid"],
        )
        self.assertEqual(
            json.loads(messages[0]["message_content"]),
            state["diagnostic_report"].model_dump(),
        )
        self.assertEqual(
            json.loads(messages[1]["message_content"]),
            state["proposed_action"].model_dump(),
        )

        decision = decisions[0]
        self.assertEqual(json.loads(decision["policy_result"])["decision"], "allow")
        json.loads(decision["provenance_result"])
        self.assertEqual(decision["final_decision"], state["workflow_result"].final_decision)
        self.assertEqual(decision["action_id"], state["workflow_result"].proposed_action.action_id)
        self.assertEqual(decision["is_injected_attack"], int(expected_attack is not None))
        self.assertEqual(decision["attack_type"], expected_attack)
        self.assertEqual(observation[0]["timestamp"], decision["timestamp"])
        self.assertTrue(
            {
                "voltage_pu",
                "load_kw",
                "solar_kw",
                "battery_soc_pct",
                "battery_temperature_c",
                "transformer_loading_pct",
            } <= observation[0].keys()
        )
        if expected_attack:
            self.assertEqual(attacks[0]["attack_type"], expected_attack)
            self.assertEqual(attacks[0]["ground_truth"], 1)
            self.assertEqual(attacks[0]["start_time"], attacks[0]["end_time"])
            self.assertEqual(attacks[0]["start_time"], "02:21")

    def test_normal_workflow_persists_expected_records(self):
        state, _ = self.run_workflow_with_persistence("10:00")
        self.assert_one_completed_audit_record(state, expected_attack=None)
        observation = sqlite_db.query_recent_observations(1, self.db_path)[0]
        self.assertEqual(observation["timestamp"], "10:00")

    def test_sensor_poisoning_workflow_persists_attacked_observation(self):
        state, monitor = self.run_workflow_with_persistence("02:21")
        self.assert_one_completed_audit_record(state, expected_attack="sensor_poisoning")
        persisted = sqlite_db.query_recent_observations(1, self.db_path)[0]
        monitored = monitor.call_args.args[0].current
        self.assertEqual(persisted["battery_temperature_c"], 92.5)
        self.assertEqual(monitored["battery_temperature_c"], 92.5)
        self.assertEqual(persisted["timestamp"], "02:21")

    def test_each_execution_gets_a_distinct_run_id(self):
        first, _ = self.run_workflow_with_persistence("10:00")
        second, _ = self.run_workflow_with_persistence("10:00")

        self.assertNotEqual(first["run_id"], second["run_id"])
        self.assertNotEqual(
            first["observation"]["run_id"],
            second["observation"]["run_id"],
        )

    def test_scheduled_replay_is_audited_excluded_and_blocked(self):
        latest_accepted = {
            "timestamp": "12:00",
            "voltage_pu": 1.0,
            "load_kw": 25.0,
            "solar_kw": 5.0,
            "battery_soc_pct": 60.0,
            "battery_temperature_c": 30.0,
            "transformer_loading_pct": 12.0,
        }
        sqlite_db.insert_observation(
            sqlite_db.ObservationRow(
                **latest_accepted,
                fingerprint=sqlite_db.observation_fingerprint(latest_accepted),
            ),
            db_path=self.db_path,
        )

        state, monitor = self.run_workflow_with_persistence("20:11")

        replay_result = state["replay_result"]
        self.assertTrue(replay_result.detected)
        self.assertEqual(replay_result.observation_timestamp, "04:00")
        self.assertEqual(replay_result.run_id, state["run_id"])
        self.assertIn("predates", replay_result.reason)
        self.assertEqual(state["observation"]["timestamp"], "04:00")
        self.assertEqual(monitor.call_args.args[0].current["timestamp"], "04:00")
        self.assertTrue(state["risk_result"].replay_detected)
        self.assertEqual(state["risk_result"].score, 1.0)
        self.assertEqual(state["risk_result"].band, "HIGH")
        self.assertEqual(state["workflow_result"].final_decision, "block")

        audit_connection = sqlite3.connect(self.db_path)
        try:
            replay_row = audit_connection.execute(
                """SELECT fingerprint, replay_detected, replay_reason, run_id
                   FROM observations WHERE timestamp = '04:00'"""
            ).fetchone()
        finally:
            audit_connection.close()
        self.assertIsNotNone(replay_row)
        self.assertEqual(len(replay_row[0]), 64)  # SHA-256 fingerprint
        self.assertEqual(replay_row[1], 1)  # replay_detected
        self.assertIn("predates", replay_row[2])  # replay_reason
        self.assertEqual(replay_row[3], state["run_id"])

        trusted_history = sqlite_db.query_recent_observations(10, self.db_path)
        self.assertTrue(all(row["timestamp"] != "04:00" for row in trusted_history))


if __name__ == "__main__":
    unittest.main()