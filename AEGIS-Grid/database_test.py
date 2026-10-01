"""Isolated tests for the SQLite schema and persistence helpers."""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from agents.schemas import MonitoringReport, ProposedAction
from aegis.behaviour import BehaviourResult
from aegis.policy import PolicyResult
from aegis.provenance import ProvenanceResult
from aegis.risk import RiskResult
from database.models import (
    AEGISDecisionRow,
    AgentMessageRow,
    AttackEventRow,
    ObservationRow,
)
from database.sqlite import (
    init_db,
    insert_aegis_decision,
    insert_agent_message,
    insert_attack_event,
    insert_observation,
    query_recent_agent_messages,
    query_recent_attack_events,
    query_recent_decisions,
    query_recent_observations,
)


class SQLitePersistenceTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "nested" / "audit.db")
        init_db(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

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
