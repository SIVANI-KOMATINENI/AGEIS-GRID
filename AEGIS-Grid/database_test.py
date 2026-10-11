"""Isolated tests for the SQLite schema and persistence helpers."""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from agents.schemas import MonitoringReport, ProposedAction
from aegis.behaviour import (
    BehaviourResult,
    analyze_behaviour,
    load_behaviour_history_from_db,
    reset_behaviour_history,
)
from aegis.policy import PolicyResult
from aegis.provenance import ProvenanceResult
from aegis.risk import RiskResult
from database.models import (
    AEGISDecisionRow,
    AgentMessageRow,
    AttackEventRow,
    ObservationRow,
    ReplayCheckResult,
)
from database.sqlite import (
    check_observation_replay,
    get_active_session_id,
    init_db,
    insert_aegis_decision,
    insert_agent_message,
    insert_attack_event,
    insert_observation,
    observation_fingerprint,
    query_recent_agent_messages,
    query_recent_attack_events,
    query_recent_decisions,
    query_recent_observations,
    record_observation_with_replay_check,
    set_active_session_id,
    start_simulation_session,
)


class SQLitePersistenceTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "nested" / "audit.db")
        init_db(self.db_path)

    def tearDown(self):
        reset_behaviour_history()
        set_active_session_id(None)
        self.temp_dir.cleanup()

    def telemetry(self, timestamp: str, temperature: float = 30.0) -> dict:
        return {
            "timestamp": timestamp,
            "voltage_pu": 1.01,
            "load_kw": 25.0,
            "solar_kw": 5.0,
            "battery_soc_pct": 60.0,
            "battery_temperature_c": temperature,
            "transformer_loading_pct": 12.0,
        }

    def insert_accepted_observation(self, observation: dict):
        insert_observation(
            ObservationRow(
                **observation,
                run_id="accepted-run",
                fingerprint=observation_fingerprint(observation),
            ),
            self.db_path,
        )


    def test_initialization_creates_four_tables(self):
        connection = sqlite3.connect(self.db_path)
        try:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        finally:
            connection.close()
        self.assertTrue(
            {"observations", "agent_messages", "attack_events", "aegis_decisions"}
            <= tables
        )

    def test_init_adds_run_id_to_legacy_table_without_losing_rows(self):
        legacy_path = str(Path(self.temp_dir.name) / "legacy.db")
        connection = sqlite3.connect(legacy_path)
        connection.execute(
            """CREATE TABLE observations (
                obs_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                voltage_pu REAL,
                load_kw REAL,
                solar_kw REAL,
                battery_soc_pct REAL,
                battery_temperature_c REAL,
                transformer_loading_pct REAL
            )"""
        )
        connection.execute(
            "INSERT INTO observations (timestamp, voltage_pu) VALUES (?, ?)",
            ("09:00", 1.01),
        )
        connection.commit()
        connection.close()

        init_db(legacy_path)

        connection = sqlite3.connect(legacy_path)
        try:
            columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(observations)")
            }
            row = connection.execute(
                "SELECT timestamp, voltage_pu, run_id FROM observations"
            ).fetchone()
        finally:
            connection.close()

        self.assertIn("run_id", columns)
        self.assertEqual(row, ("09:00", 1.01, None))

    def test_observation_insert_and_retrieval(self):
        observation = ObservationRow(
            run_id="run-observation",
            timestamp="10:00",
            voltage_pu=1.02,
            load_kw=45.0,
            solar_kw=10.0,
            battery_soc_pct=85.0,
            battery_temperature_c=31.2,
            transformer_loading_pct=15.0,
        )
        insert_observation(observation, self.db_path)
        rows = query_recent_observations(5, self.db_path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["timestamp"], "10:00")
        self.assertEqual(rows[0]["run_id"], "run-observation")
        self.assertEqual(rows[0]["battery_temperature_c"], 31.2)

    def test_fresh_observation_is_accepted_with_extra_fields_ignored(self):
        observation = self.telemetry("10:00")
        result = check_observation_replay(observation, self.db_path)
        self.assertFalse(result.detected)
        self.assertEqual(result.observation_timestamp, "10:00")
        self.assertEqual(len(result.fingerprint), 64)
        self.assertEqual(
            observation_fingerprint({**observation, "run_id": "other", "metadata": "ignored"}),
            result.fingerprint,
        )

    def test_duplicate_fingerprint_is_detected_via_helper(self):
        observation = self.telemetry("10:00")
        self.insert_accepted_observation(observation)

        result = check_observation_replay(observation, self.db_path)
        self.assertTrue(result.detected)
        self.assertIn("Duplicate", result.reason)

    def test_stale_timestamp_is_detected_via_helper(self):
        self.insert_accepted_observation(self.telemetry("10:30"))

        result = check_observation_replay(
            self.telemetry("04:00", temperature=85.0),
            self.db_path,
        )
        self.assertTrue(result.detected)
        self.assertIn("predates", result.reason)

    def test_newer_timestamp_is_accepted_via_helper(self):
        self.insert_accepted_observation(self.telemetry("10:00"))

        result = check_observation_replay(self.telemetry("10:01"), self.db_path)
        self.assertFalse(result.detected)

    def test_fingerprint_replay_persists_across_connections(self):
        observation = self.telemetry("10:00")
        self.insert_accepted_observation(observation)

        result = check_observation_replay(observation, self.db_path)
        self.assertTrue(result.detected)
        self.assertIn("Duplicate", result.reason)

    def test_atomic_record_accepts_once_and_audits_duplicate(self):
        observation = self.telemetry("10:00")
        first = record_observation_with_replay_check(
            ObservationRow(
                **observation,
                run_id="run-first",
            ),
            db_path=self.db_path,
        )
        second = record_observation_with_replay_check(
            ObservationRow(
                **observation,
                run_id="run-second",
            ),
            db_path=self.db_path,
        )

        self.assertFalse(first.detected)
        self.assertTrue(second.detected)
        self.assertIn("Duplicate", second.reason)
        connection = sqlite3.connect(self.db_path)
        try:
            replay_statuses = connection.execute(
                "SELECT replay_detected FROM observations ORDER BY obs_id"
            ).fetchall()
        finally:
            connection.close()
        self.assertEqual(replay_statuses, [(0,), (1,)])

    def test_replayed_observation_is_audited_but_not_trusted_history(self):
        accepted = self.telemetry("12:00")
        self.insert_accepted_observation(accepted)
        observation = self.telemetry("04:00", temperature=85.0)
        result = check_observation_replay(observation, self.db_path)
        self.assertTrue(result.detected)
        insert_observation(
            ObservationRow(
                **observation,
                run_id="replay-run",
                fingerprint=result.fingerprint,
                replay_detected=result.detected,
                replay_reason=result.reason if result.detected else None,
            ),
            self.db_path,
        )

        connection = sqlite3.connect(self.db_path)
        try:
            audit_row = connection.execute(
                "SELECT replay_detected, replay_reason FROM observations ORDER BY obs_id DESC LIMIT 1"
            ).fetchone()
        finally:
            connection.close()
        self.assertIsNotNone(audit_row)
        self.assertEqual(audit_row[0], 1)
        self.assertIn("predates", audit_row[1])
        trusted_history = query_recent_observations(10, self.db_path)
        self.assertEqual([row["timestamp"] for row in trusted_history], ["12:00"])

    def test_legitimate_new_session_accepts_identical_telemetry(self):
        telemetry = self.telemetry("10:00")

        # Session 1: first observation is accepted
        set_active_session_id("sim_session_alpha")
        first_res = record_observation_with_replay_check(
            ObservationRow(**telemetry, run_id="run_s1_1"),
            session_id="sim_session_alpha",
            db_path=self.db_path,
        )
        self.assertFalse(first_res.detected)
        self.assertEqual(first_res.session_id, "sim_session_alpha")

        # Session 1: identical telemetry within the same session is flagged as duplicate replay
        dup_res = record_observation_with_replay_check(
            ObservationRow(**telemetry, run_id="run_s1_2"),
            session_id="sim_session_alpha",
            db_path=self.db_path,
        )
        self.assertTrue(dup_res.detected)
        self.assertIn("Duplicate", dup_res.reason)

        # Session 2: A new simulation session boundary is started
        start_simulation_session("sim_session_beta", db_path=self.db_path)

        # Session 2: identical telemetry from the new session is legitimately accepted
        new_session_res = record_observation_with_replay_check(
            ObservationRow(**telemetry, run_id="run_s2_1"),
            session_id="sim_session_beta",
            db_path=self.db_path,
        )
        self.assertFalse(new_session_res.detected)
        self.assertEqual(new_session_res.session_id, "sim_session_beta")

        # Session 2: timestamp regression within the new session is detected
        advance_res = record_observation_with_replay_check(
            ObservationRow(**self.telemetry("10:30"), run_id="run_s2_2"),
            session_id="sim_session_beta",
            db_path=self.db_path,
        )
        self.assertFalse(advance_res.detected)

        regress_res = record_observation_with_replay_check(
            ObservationRow(**self.telemetry("10:15"), run_id="run_s2_3"),
            session_id="sim_session_beta",
            db_path=self.db_path,
        )
        self.assertTrue(regress_res.detected)
        self.assertIn("predates", regress_res.reason)

    def test_persisted_behaviour_history_loads_from_db(self):
        # Insert historical actions for response_agent into test DB
        baseline_action1 = ProposedAction(
            action_id="act_hist_1",
            sender_agent="response_agent",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="Historical baseline 1",
            priority="LOW",
        )
        baseline_action2 = ProposedAction(
            action_id="act_hist_2",
            sender_agent="response_agent",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="Historical baseline 2",
            priority="LOW",
        )
        insert_agent_message(
            AgentMessageRow(
                run_id="run_hist_1",
                timestamp="09:00",
                sender_agent="response_agent",
                receiver_agent="aegis_grid",
                message_content=baseline_action1.model_dump_json(),
            ),
            self.db_path,
        )
        insert_agent_message(
            AgentMessageRow(
                run_id="run_hist_2",
                timestamp="09:01",
                sender_agent="response_agent",
                receiver_agent="aegis_grid",
                message_content=baseline_action2.model_dump_json(),
            ),
            self.db_path,
        )

        # 1. Verify isolated tests do NOT load from DB when enable_db_load=False
        reset_behaviour_history(enable_db_load=False, db_path=self.db_path)
        test_action = ProposedAction(
            action_id="act_test_iso",
            sender_agent="response_agent",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="Isolated action",
            priority="LOW",
        )
        iso_res = analyze_behaviour(test_action)
        # Should pass by default because no history was loaded
        self.assertFalse(iso_res.flagged)
        self.assertIn("No baseline history yet", iso_res.deviation_reason or "")

        # 2. Verify normal run / reload loads persisted history from DB
        reset_behaviour_history(enable_db_load=True, db_path=self.db_path)
        loaded_count = load_behaviour_history_from_db("response_agent", db_path=self.db_path)
        self.assertEqual(loaded_count, 2)

        # 3. An unseen action type against the loaded history should now be flagged
        novel_action = ProposedAction(
            action_id="act_test_novel",
            sender_agent="response_agent",
            action_type="ISOLATE_BATTERY",
            target="battery_1",
            reason="Testing anomaly against persisted baseline",
            priority="MEDIUM",
        )
        novel_res = analyze_behaviour(novel_action)
        self.assertTrue(novel_res.flagged)
        self.assertIn("never seen in recent history", novel_res.deviation_reason)

    def test_agent_messages_are_model_json_and_queryable(self):
        report = MonitoringReport(
            run_id="run-messages",
            report_id="rep_10:00",
            timestamp="10:00",
            status="NORMAL",
            severity="NONE",
            confidence=1.0,
        )
        action = ProposedAction(
            action_id="act_10:00",
            run_id="run-messages",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="Normal operation.",
            priority="LOW",
        )
        for sender, receiver, model in (
            ("monitoring_agent", "response_agent", report),
            ("response_agent", "aegis_grid", action),
        ):
            insert_agent_message(
                AgentMessageRow(
                    run_id="run-messages",
                    timestamp="10:00",
                    sender_agent=sender,
                    receiver_agent=receiver,
                    message_content=model.model_dump_json(),
                ),
                self.db_path,
            )

        messages = query_recent_agent_messages(5, self.db_path)
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0]["receiver_agent"], "response_agent")
        self.assertEqual(messages[1]["receiver_agent"], "aegis_grid")
        self.assertEqual({message["run_id"] for message in messages}, {"run-messages"})
        self.assertEqual(json.loads(messages[0]["message_content"])["status"], "NORMAL")
        self.assertEqual(json.loads(messages[1]["message_content"])["action_id"], "act_10:00")

    def test_attack_event_ground_truth(self):
        insert_attack_event(
            AttackEventRow(
                run_id="run-attack",
                attack_type="sensor_poisoning",
                target="observation",
                start_time="02:21",
                end_time="02:21",
            ),
            self.db_path,
        )
        events = query_recent_attack_events(5, self.db_path)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["attack_type"], "sensor_poisoning")
        self.assertEqual(events[0]["ground_truth"], 1)
        self.assertEqual(events[0]["run_id"], "run-attack")
        self.assertEqual(events[0]["start_time"], events[0]["end_time"])

    def test_decision_json_and_fields_are_queryable(self):
        policy = PolicyResult(decision="allow", reason="Policy passed.")
        provenance = ProvenanceResult(
            verified=True,
            trace_length=1,
            reason="Verified.",
        )
        behaviour = BehaviourResult(flagged=False)
        risk = RiskResult(
            score=0.0,
            band="LOW",
            contributing_factors={"policy": 0.0, "provenance": 0.0, "behaviour": 0.0},
        )
        insert_aegis_decision(
            AEGISDecisionRow(
                run_id="run-decision",
                timestamp="10:00",
                action_id="act_10:00",
                policy_result=policy.model_dump_json(),
                provenance_result=provenance.model_dump_json(),
                behaviour_flag=int(behaviour.flagged),
                risk_score=risk.score,
                final_decision="allow",
                reason="Approved.",
                human_reviewer=None,
                is_injected_attack=0,
                attack_type=None,
            ),
            self.db_path,
        )
        decisions = query_recent_decisions(5, self.db_path)
        self.assertEqual(len(decisions), 1)
        self.assertEqual(json.loads(decisions[0]["policy_result"])["decision"], "allow")
        self.assertTrue(json.loads(decisions[0]["provenance_result"])["verified"])
        self.assertEqual(decisions[0]["final_decision"], "allow")
        self.assertEqual(decisions[0]["run_id"], "run-decision")
        self.assertEqual(decisions[0]["is_injected_attack"], 0)
        self.assertIsNone(decisions[0]["human_reviewer"])


if __name__ == "__main__":
    unittest.main()
