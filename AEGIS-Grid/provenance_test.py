"""Isolated tests for fail-closed Neo4j action provenance verification."""

import unittest
from unittest.mock import MagicMock, Mock, patch

from agents.schemas import ProposedAction
from aegis.provenance import verify_provenance
from attacks.authority_spoofing import apply_authority_spoofing
from provenance.neo4j_client import Neo4jClient


class ProvenanceVerificationTest(unittest.TestCase):
    def setUp(self):
        self.action = ProposedAction(
            action_id="act_run_1",
            run_id="run_1",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Test proposal",
            priority="MEDIUM",
            claimed_authorization="rep_run_1",
        )

    def make_client(self, record):
        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        session = Mock()
        client.driver.session.return_value.__enter__.return_value = session
        session.run.return_value.single.return_value = record
        return client, session

    def test_complete_report_to_action_chain_verifies(self):
        record = {
            "report_exists": True,
            "monitoring_link_exists": True,
            "response_link_exists": True,
            "action_exists": True,
            "claim_matches": True,
        }
        client, session = self.make_client(record)

        with patch("aegis.provenance.get_neo4j_client", return_value=client):
            result = verify_provenance(self.action)

        self.assertTrue(result.verified)
        self.assertEqual(result.trace_length, 3)
        query = session.run.call_args.args[0]
        self.assertIn("(m:MonitoringAgent {run_id: $run_id})-[:GENERATED]->(r)", query)
        self.assertIn(
            "(r)-[:RECEIVED_BY]->(res:ResponseAgent {run_id: $run_id})",
            query,
        )
        self.assertIn(
            "-[:PROPOSED]->(a:Action {id: $action_id, run_id: $run_id})",
            query,
        )
        self.assertNotIn("AEGISDecision", query)
        self.assertNotIn("authorization_token", query)
        self.assertEqual(
            session.run.call_args.kwargs,
            {
                "claimed_authorization": "rep_run_1",
                "action_id": "act_run_1",
                "run_id": "run_1",
            },
        )

    def test_missing_report_fails(self):
        record = {
            "report_exists": False,
            "monitoring_link_exists": False,
            "response_link_exists": False,
            "action_exists": False,
            "claim_matches": False,
        }
        client, _ = self.make_client(record)
        with patch("aegis.provenance.get_neo4j_client", return_value=client):
            result = verify_provenance(self.action)
        self.assertFalse(result.verified)
        self.assertIn("claimed report does not exist", result.reason)

    def test_existing_report_not_linked_to_action_fails(self):
        record = {
            "report_exists": True,
            "monitoring_link_exists": True,
            "response_link_exists": False,
            "action_exists": False,
            "claim_matches": False,
        }
        client, _ = self.make_client(record)
        with patch("aegis.provenance.get_neo4j_client", return_value=client):
            result = verify_provenance(self.action)
        self.assertFalse(result.verified)
        self.assertIn("report exists but is not linked", result.reason)

    def test_wrong_action_id_fails(self):
        record = {
            "report_exists": True,
            "monitoring_link_exists": True,
            "response_link_exists": True,
            "action_exists": False,
            "claim_matches": False,
        }
        client, _ = self.make_client(record)
        with patch("aegis.provenance.get_neo4j_client", return_value=client):
            result = verify_provenance(self.action)
        self.assertFalse(result.verified)

    def test_legacy_report_id_cannot_authorize_unrelated_action(self):
        legacy_action = self.action.model_copy(
            update={"claimed_authorization": "rep_unknown"}
        )
        record = {
            "report_exists": True,
            "monitoring_link_exists": True,
            "response_link_exists": True,
            "action_exists": True,
            "claim_matches": False,
        }
        client, _ = self.make_client(record)
        with patch("aegis.provenance.get_neo4j_client", return_value=client):
            result = verify_provenance(legacy_action)
        self.assertFalse(result.verified)

    def test_missing_claim_fails(self):
        action = self.action.model_copy(update={"claimed_authorization": None})
        with patch("aegis.provenance.get_neo4j_client") as get_client:
            result = verify_provenance(action)
        get_client.assert_not_called()
        self.assertFalse(result.verified)

    def test_neo4j_unavailable_fails_closed(self):
        client = Mock()
        client.driver = None
        with patch("aegis.provenance.get_neo4j_client", return_value=client):
            result = verify_provenance(self.action)
        self.assertFalse(result.verified)
        self.assertIn("Neo4j is unavailable", result.reason)

    def test_authority_spoofing_still_fails_provenance(self):
        spoofed = apply_authority_spoofing(self.action)
        client = Mock()
        client.driver = Mock()
        client.authorization_status.return_value = "report_missing"

        with patch("aegis.provenance.get_neo4j_client", return_value=client):
            result = verify_provenance(spoofed)

        self.assertEqual(spoofed.run_id, self.action.run_id)
        self.assertEqual(spoofed.claimed_authorization, "auth_tok_hacked_admin_999")
        self.assertFalse(result.verified)
        client.authorization_status.assert_called_once_with(
            spoofed.claimed_authorization,
            spoofed.action_id,
            spoofed.run_id,
        )

    def test_writer_scopes_provenance_nodes_by_run_id(self):
        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        observation = {"timestamp": "10:00", "run_id": "run_writer"}
        report = {
            "run_id": "run_writer",
            "report_id": "rep_10:00",
            "status": "NORMAL",
            "severity": "NONE",
        }
        action = {
            "run_id": "run_writer",
            "action_id": "act_10:00",
            "action_type": "MAINTAIN_STATUS",
            "target": "none",
            "claimed_authorization": "rep_10:00",
        }

        client.log_action_provenance(observation, report, action)

        query, parameters = client.driver.session.return_value.__enter__.return_value.run.call_args.args
        self.assertIn("run_id: $run_id", query)
        self.assertEqual(parameters["run_id"], "run_writer")


if __name__ == "__main__":
    unittest.main()