from datetime import datetime, timezone
import unittest
from unittest.mock import MagicMock, Mock, patch

from agents.schemas import ProposedAction, AuthorizationEvidence
from aegis.personnel import build_default_registry
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


class PersonnelProvenanceIntegrationTest(unittest.TestCase):
    """
    Focused integration tests verifying that verify_provenance() properly
    routes personnel authorization evidence through verify_personnel_authority(),
    returns explicit provenance failure statuses, keeps personnel and report channels
    strictly distinct, and never queries Neo4j for personnel claims.
    """

    def setUp(self):
        self.registry = build_default_registry()
        self.signing_auth = self.registry.signing_authority
        self.test_now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

    def test_personnel_valid_authorization_verified(self):
        """Valid personnel credential produces verified provenance without querying Neo4j."""
        action = ProposedAction(
            action_id="act_pers_01",
            run_id="run_p1",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Dispatcher peak shaving",
            priority="HIGH",
            parameters={"reduction_kw": 150.0},
        )
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_prov_01",
        )

        with patch("aegis.provenance.get_neo4j_client") as mock_neo:
            result = verify_provenance(action, personnel_registry=self.registry, now=self.test_now)

        mock_neo.assert_not_called()
        self.assertTrue(result.verified)
        self.assertEqual(result.status, "verified")
        self.assertEqual(result.auth_type, "personnel")
        self.assertEqual(result.personnel_id, "PERS-001")
        self.assertEqual(result.role, "Lead Grid Dispatcher")
        self.assertIn("Personnel authority verified", result.reason)

    def test_personnel_unknown_fails(self):
        """Unknown personnel ID produces explicit unknown_personnel status."""
        action = ProposedAction(
            action_id="act_pers_02",
            run_id="run_p2",
            action_type="INSPECT",
            target="battery_1",
            reason="Check",
            priority="LOW",
        )
        action.authorization_evidence = AuthorizationEvidence(
            token_type="PERSONNEL_CREDENTIAL",
            personnel_id="PERS-999-GHOST",
            signature="sig_fake",
            issued_at=self.test_now.isoformat(),
            nonce="nonce_02",
        )

        with patch("aegis.provenance.get_neo4j_client") as mock_neo:
            result = verify_provenance(action, personnel_registry=self.registry, now=self.test_now)

        mock_neo.assert_not_called()
        self.assertFalse(result.verified)
        self.assertEqual(result.status, "unknown_personnel")
        self.assertEqual(result.auth_type, "personnel")
        self.assertIn("not recognized", result.reason)

    def test_personnel_invalid_signature_fails(self):
        """Forged or invalid signature produces explicit invalid_signature status."""
        action = ProposedAction(
            action_id="act_pers_03",
            run_id="run_p3",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Malicious curtailment",
            priority="HIGH",
            parameters={"reduction_kw": 50.0},
        )
        action.authorization_evidence = AuthorizationEvidence(
            token_type="PERSONNEL_CREDENTIAL",
            personnel_id="PERS-001",
            signature="forged_signature_attacker_key",
            issued_at=self.test_now.isoformat(),
            nonce="nonce_03",
        )

        with patch("aegis.provenance.get_neo4j_client") as mock_neo:
            result = verify_provenance(action, personnel_registry=self.registry, now=self.test_now)

        mock_neo.assert_not_called()
        self.assertFalse(result.verified)
        self.assertEqual(result.status, "invalid_signature")
        self.assertIn("signature verification failed", result.reason)

    def test_personnel_tampered_action_fails(self):
        """Payload modified after signing produces action_digest_mismatch status."""
        action = ProposedAction(
            action_id="act_pers_04",
            run_id="run_p4",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Curtailment",
            priority="HIGH",
            parameters={"reduction_kw": 50.0},
        )
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_04",
        )
        # Tamper with action parameter
        action.parameters["reduction_kw"] = 200.0

        with patch("aegis.provenance.get_neo4j_client") as mock_neo:
            result = verify_provenance(action, personnel_registry=self.registry, now=self.test_now)

        mock_neo.assert_not_called()
        self.assertFalse(result.verified)
        self.assertEqual(result.status, "action_digest_mismatch")
        self.assertIn("tampered", result.reason)

    def test_personnel_revoked_credential_fails(self):
        """Revoked credential produces explicit revoked_credential status."""
        action = ProposedAction(
            action_id="act_pers_05",
            run_id="run_p5",
            action_type="INSPECT",
            target="none",
            reason="Inspection",
            priority="LOW",
        )
        # PERS-005 is revoked
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-005",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_05",
        )

        with patch("aegis.provenance.get_neo4j_client") as mock_neo:
            result = verify_provenance(action, personnel_registry=self.registry, now=self.test_now)

        mock_neo.assert_not_called()
        self.assertFalse(result.verified)
        self.assertEqual(result.status, "revoked_credential")
        self.assertIn("revoked or deactivated", result.reason)

    def test_personnel_expired_credential_fails(self):
        """Expired credential produces explicit expired_credential status."""
        action = ProposedAction(
            action_id="act_pers_06",
            run_id="run_p6",
            action_type="INSPECT",
            target="battery_1",
            reason="Post-expiration inspection",
            priority="LOW",
        )
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at="2027-01-10T00:00:00Z",
            nonce="nonce_06",
        )
        future_time = datetime(2027, 2, 1, 0, 0, 0, tzinfo=timezone.utc)

        with patch("aegis.provenance.get_neo4j_client") as mock_neo:
            result = verify_provenance(action, personnel_registry=self.registry, now=future_time)

        mock_neo.assert_not_called()
        self.assertFalse(result.verified)
        self.assertEqual(result.status, "expired_credential")

    def test_personnel_unauthorized_action_fails(self):
        """Out-of-scope action type produces explicit unauthorized_action status."""
        action = ProposedAction(
            action_id="act_pers_07",
            run_id="run_p7",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Field tech load reduction attempt",
            priority="MEDIUM",
            parameters={"reduction_kw": 20.0},
        )
        # PERS-002 only permitted for INSPECT, LOG_WARNING, INVESTIGATE, MAINTAIN_STATUS
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-002",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_07",
        )

        with patch("aegis.provenance.get_neo4j_client") as mock_neo:
            result = verify_provenance(action, personnel_registry=self.registry, now=self.test_now)

        mock_neo.assert_not_called()
        self.assertFalse(result.verified)
        self.assertEqual(result.status, "unauthorized_action")
        self.assertIn("outside permitted actions", result.reason)

    def test_personnel_unauthorized_target_fails(self):
        """Out-of-scope target component produces explicit unauthorized_target status."""
        action = ProposedAction(
            action_id="act_pers_08",
            run_id="run_p8",
            action_type="REDUCE_LOAD",
            target="critical_load",
            reason="Curtail critical facility",
            priority="HIGH",
            parameters={"reduction_kw": 50.0},
        )
        # PERS-001 targets: load_1, battery_1, none (NOT critical_load)
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_08",
        )

        with patch("aegis.provenance.get_neo4j_client") as mock_neo:
            result = verify_provenance(action, personnel_registry=self.registry, now=self.test_now)

        mock_neo.assert_not_called()
        self.assertFalse(result.verified)
        self.assertEqual(result.status, "unauthorized_target")
        self.assertIn("outside permitted targets", result.reason)

    def test_personnel_priority_exceeded_fails(self):
        """Priority exceeding authorized ceiling produces explicit priority_exceeded status."""
        action = ProposedAction(
            action_id="act_pers_09",
            run_id="run_p9",
            action_type="INSPECT",
            target="battery_1",
            reason="High priority inspection",
            priority="HIGH",
        )
        # PERS-002 ceiling is MEDIUM
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-002",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_09",
        )

        with patch("aegis.provenance.get_neo4j_client") as mock_neo:
            result = verify_provenance(action, personnel_registry=self.registry, now=self.test_now)

        mock_neo.assert_not_called()
        self.assertFalse(result.verified)
        self.assertEqual(result.status, "priority_exceeded")

    def test_personnel_parameter_limit_exceeded_fails(self):
        """Parameters exceeding limits produce explicit parameter_exceeded status."""
        action = ProposedAction(
            action_id="act_pers_10",
            run_id="run_p10",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Over-limit curtailment",
            priority="HIGH",
            parameters={"reduction_kw": 300.0},
        )
        # PERS-001 max load reduction is 250.0 kW
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_10",
        )

        with patch("aegis.provenance.get_neo4j_client") as mock_neo:
            result = verify_provenance(action, personnel_registry=self.registry, now=self.test_now)

        mock_neo.assert_not_called()
        self.assertFalse(result.verified)
        self.assertEqual(result.status, "parameter_exceeded")
        self.assertIn("exceeds authorized limit", result.reason)

    def test_personnel_missing_co_approval_fails(self):
        """Action requiring co-approval without co-signer produces missing_co_approval status."""
        action = ProposedAction(
            action_id="act_pers_11",
            run_id="run_p11",
            action_type="SHUTDOWN_LOAD",
            target="load_1",
            reason="Shutdown without supervisor co-approval",
            priority="HIGH",
        )
        # PERS-004 requires co-approval for SHUTDOWN_LOAD
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-004",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_11",
        )

        with patch("aegis.provenance.get_neo4j_client") as mock_neo:
            result = verify_provenance(action, personnel_registry=self.registry, now=self.test_now)

        mock_neo.assert_not_called()
        self.assertFalse(result.verified)
        self.assertEqual(result.status, "missing_co_approval")

    def test_personnel_invalid_co_signer_fails(self):
        """Co-signer without permission for the required action produces invalid_co_signer status."""
        action = ProposedAction(
            action_id="act_pers_12",
            run_id="run_p12",
            action_type="SHUTDOWN_LOAD",
            target="load_1",
            reason="Shutdown co-signed by junior field tech",
            priority="HIGH",
        )
        # PERS-002 (Marcus Thorne) has no SHUTDOWN_LOAD permission
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-004",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_12",
            co_signer_id="PERS-002",
        )

        with patch("aegis.provenance.get_neo4j_client") as mock_neo:
            result = verify_provenance(action, personnel_registry=self.registry, now=self.test_now)

        mock_neo.assert_not_called()
        self.assertFalse(result.verified)
        self.assertEqual(result.status, "invalid_co_signer")
        self.assertIn("not authorized for action type", result.reason)

    def test_personnel_valid_co_approval_verified(self):
        """Dual-authorized action with valid authorized co-signer succeeds."""
        action = ProposedAction(
            action_id="act_pers_13",
            run_id="run_p13",
            action_type="SHUTDOWN_LOAD",
            target="load_1",
            reason="Authorized emergency shutdown",
            priority="HIGH",
        )
        # Silas Vance (PERS-004) co-approved by Elena Vance (PERS-001)
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-004",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_13",
            co_signer_id="PERS-001",
        )

        with patch("aegis.provenance.get_neo4j_client") as mock_neo:
            result = verify_provenance(action, personnel_registry=self.registry, now=self.test_now)

        mock_neo.assert_not_called()
        self.assertTrue(result.verified)
        self.assertEqual(result.status, "verified")
        self.assertEqual(result.personnel_id, "PERS-004")

    def test_claimed_personnel_id_without_evidence_rejected(self):
        """
        Claimed personnel ID string in claimed_authorization without cryptographic
        evidence is rejected upfront and NEVER queried as a report in Neo4j.
        """
        action = ProposedAction(
            action_id="act_pers_14",
            run_id="run_p14",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Unauthenticated claimed personnel ID",
            priority="HIGH",
            claimed_authorization="PERS-001",  # Claimed without AuthorizationEvidence
        )

        with patch("aegis.provenance.get_neo4j_client") as mock_neo:
            result = verify_provenance(action, personnel_registry=self.registry, now=self.test_now)

        # Must NOT query Neo4j for a report named PERS-001
        mock_neo.assert_not_called()
        self.assertFalse(result.verified)
        self.assertEqual(result.status, "missing_credential")
        self.assertIn("requires cryptographic AuthorizationEvidence", result.reason)

    def test_failed_personnel_verification_cannot_fall_back_to_report(self):
        """
        Failed personnel verification must fail-closed immediately and NEVER
        produce a verified result even if claimed_authorization names a report.
        """
        action = ProposedAction(
            action_id="act_pers_15",
            run_id="run_p15",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Dual claim with invalid personnel signature",
            priority="HIGH",
            parameters={"reduction_kw": 50.0},
            claimed_authorization="rep_valid_report_123",  # Report also present
        )
        action.authorization_evidence = AuthorizationEvidence(
            token_type="PERSONNEL_CREDENTIAL",
            personnel_id="PERS-001",
            signature="invalid_signature_tampered",
            issued_at=self.test_now.isoformat(),
            nonce="nonce_15",
        )

        with patch("aegis.provenance.get_neo4j_client") as mock_neo:
            result = verify_provenance(action, personnel_registry=self.registry, now=self.test_now)

        # Personnel verification failure is final; must never fall through to report
        mock_neo.assert_not_called()
        self.assertFalse(result.verified)
        self.assertEqual(result.status, "invalid_signature")


if __name__ == "__main__":
    unittest.main()