"""
personnel_test.py
Focused unit tests for the AEGIS GRID Personnel Authority Registry (Step 1).

Covers:
- Unknown personnel
- Missing or invalid signatures
- In-flight action tampering
- Revoked and expired credentials
- Authorized vs unauthorized actions
- Target scope restrictions
- Priority limit enforcement
- Parameter limit enforcement (load reduction, negative values)
- Dual-authorization / co-approval requirement & enforcement
- Valid multi-party authorization
- High experience / executive designation alone not granting authority
- Backward compatibility for actions without personnel evidence
"""

import unittest
from datetime import datetime, timezone

from agents.schemas import ProposedAction, AuthorizationEvidence, compute_action_digest
from aegis.personnel import (
    PersonnelRecord,
    ParameterLimits,
    PersonnelAuthorityRegistry,
    SimulatedSigningAuthority,
    build_default_registry,
    verify_personnel_authority,
)


class TestPersonnelAuthorityRegistry(unittest.TestCase):

    def setUp(self) -> None:
        self.registry = build_default_registry()
        self.signing_auth = self.registry.signing_authority
        # Deterministic timestamp within 2026 operational validity window
        self.test_now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

    # ── Authentication Gate Tests (Gate 1) ────────────────────────────────────

    def test_missing_credential_on_unauthenticated_action(self) -> None:
        """Actions lacking authorization evidence must fail authentication immediately."""
        action = ProposedAction(
            action_id="act_001",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Peak shaving",
            priority="HIGH",
            parameters={"reduction_kw": 50.0},
        )
        result = verify_personnel_authority(action, self.registry, self.test_now)
        self.assertFalse(result.is_authenticated)
        self.assertFalse(result.is_authorized)
        self.assertEqual(result.status_code, "MISSING_CREDENTIAL")
        self.assertIn("No authorization evidence", result.failure_reason or "")

    def test_unknown_personnel_rejected(self) -> None:
        """Unrecognized personnel ID must fail authentication."""
        action = ProposedAction(
            action_id="act_002",
            action_type="INSPECT",
            target="battery_1",
            reason="Routine check",
            priority="LOW",
        )
        action.authorization_evidence = AuthorizationEvidence(
            token_type="PERSONNEL_CREDENTIAL",
            personnel_id="PERS-UNKNOWN-999",
            signature="sig_dummy",
            issued_at=self.test_now.isoformat(),
            nonce="nonce_123",
        )
        result = verify_personnel_authority(action, self.registry, self.test_now)
        self.assertFalse(result.is_authenticated)
        self.assertFalse(result.is_authorized)
        self.assertEqual(result.status_code, "UNKNOWN_PERSONNEL")
        self.assertEqual(result.personnel_id, "PERS-UNKNOWN-999")

    def test_missing_signature_rejected(self) -> None:
        """A valid personnel ID with missing signature must never authenticate."""
        action = ProposedAction(
            action_id="act_003",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Voltage regulation",
            priority="MEDIUM",
            parameters={"reduction_kw": 50.0},
        )
        action.authorization_evidence = AuthorizationEvidence(
            token_type="PERSONNEL_CREDENTIAL",
            personnel_id="PERS-001",
            signature="",  # Missing signature
            issued_at=self.test_now.isoformat(),
            nonce="nonce_123",
        )
        result = verify_personnel_authority(action, self.registry, self.test_now)
        self.assertFalse(result.is_authenticated)
        self.assertFalse(result.is_authorized)
        self.assertEqual(result.status_code, "MISSING_SIGNATURE")
        self.assertEqual(result.personnel_id, "PERS-001")

    def test_invalid_signature_attacker_forgery(self) -> None:
        """Forged or attacker-synthesized token must fail signature verification."""
        action = ProposedAction(
            action_id="act_004",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Adversarial load reduction",
            priority="HIGH",
            parameters={"reduction_kw": 100.0},
        )
        action.authorization_evidence = AuthorizationEvidence(
            token_type="PERSONNEL_CREDENTIAL",
            personnel_id="PERS-001",
            signature="forged_hmac_signature_attacker_secret",
            issued_at=self.test_now.isoformat(),
            nonce="nonce_attack_999",
        )
        result = verify_personnel_authority(action, self.registry, self.test_now)
        self.assertFalse(result.is_authenticated)
        self.assertFalse(result.is_authorized)
        self.assertEqual(result.status_code, "INVALID_SIGNATURE")
        self.assertEqual(result.personnel_id, "PERS-001")

    def test_in_flight_action_tampering_detected(self) -> None:
        """Modifying action parameters after signing invalidates the cryptographic binding."""
        action = ProposedAction(
            action_id="act_005",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Load curtailment",
            priority="HIGH",
            parameters={"reduction_kw": 100.0},
        )
        # Legitimate signer issues evidence for 100 kW reduction
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_abc_1",
        )

        # Attacker modifies action parameters in flight
        action.parameters["reduction_kw"] = 240.0
        # If digest was not updated, action.is_digest_valid() will return False
        result = verify_personnel_authority(action, self.registry, self.test_now)
        self.assertFalse(result.is_authenticated)
        self.assertEqual(result.status_code, "TAMPERED_ACTION")

        # Even if attacker recalculates action_digest, the signature was over the old digest
        action.action_digest = compute_action_digest(
            action.action_type, action.target, action.parameters
        )
        result_recalc = verify_personnel_authority(action, self.registry, self.test_now)
        self.assertFalse(result_recalc.is_authenticated)
        self.assertEqual(result_recalc.status_code, "INVALID_SIGNATURE")

    def test_revoked_personnel_rejected(self) -> None:
        """Revoked credentials must be blocked even with valid cryptographic signatures."""
        action = ProposedAction(
            action_id="act_006",
            action_type="INSPECT",
            target="none",
            reason="Inspection attempt by revoked personnel",
            priority="LOW",
        )
        # PERS-005 (Devon Reed) is inactive in default fixtures
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-005",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_devon_1",
        )
        result = verify_personnel_authority(action, self.registry, self.test_now)
        self.assertFalse(result.is_authenticated)
        self.assertFalse(result.is_authorized)
        self.assertEqual(result.status_code, "REVOKED_CREDENTIAL")
        self.assertEqual(result.personnel_id, "PERS-005")

    def test_dynamic_credential_revocation(self) -> None:
        """Revoking an active personnel dynamically immediately invalidates authority."""
        action = ProposedAction(
            action_id="act_007",
            action_type="INSPECT",
            target="battery_1",
            reason="Inspection",
            priority="LOW",
        )
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_dyn_1",
        )

        # Verify initial valid state
        initial_res = verify_personnel_authority(action, self.registry, self.test_now)
        self.assertTrue(initial_res.is_authenticated)
        self.assertTrue(initial_res.is_authorized)

        # Revoke PERS-001
        self.assertTrue(self.registry.revoke_personnel("PERS-001"))

        # Subsequent verification fails
        revoked_res = verify_personnel_authority(action, self.registry, self.test_now)
        self.assertFalse(revoked_res.is_authenticated)
        self.assertEqual(revoked_res.status_code, "REVOKED_CREDENTIAL")

    def test_expired_credential_rejected(self) -> None:
        """Credentials evaluated outside their valid_from/valid_to window must fail."""
        action = ProposedAction(
            action_id="act_008",
            action_type="INSPECT",
            target="battery_1",
            reason="Post-expiration inspection",
            priority="LOW",
        )
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at="2027-01-15T00:00:00Z",
            nonce="nonce_exp_1",
        )
        # Evaluated in 2027 (PERS-001 validity expires 2026-12-31)
        future_eval = datetime(2027, 2, 1, 0, 0, 0, tzinfo=timezone.utc)
        result = verify_personnel_authority(action, self.registry, future_eval)
        self.assertFalse(result.is_authenticated)
        self.assertEqual(result.status_code, "EXPIRED_CREDENTIAL")

    # ── Authorization Scope Tests (Gate 2) ────────────────────────────────────

    def test_valid_authorization_success(self) -> None:
        """Authorized operator performing an in-scope action must succeed."""
        action = ProposedAction(
            action_id="act_009",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Peak shaving curtailment",
            priority="HIGH",
            parameters={"reduction_kw": 200.0},
        )
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_ok_1",
        )
        result = verify_personnel_authority(action, self.registry, self.test_now)
        self.assertTrue(result.is_authenticated)
        self.assertTrue(result.is_authorized)
        self.assertEqual(result.status_code, "AUTH_OK")
        self.assertEqual(result.personnel_id, "PERS-001")
        self.assertEqual(result.role, "Lead Grid Dispatcher")
        self.assertIsNone(result.failure_reason)

    def test_unauthorized_action_rejected(self) -> None:
        """Authenticated personnel attempting an out-of-scope action type must be denied."""
        # PERS-002 (Marcus Thorne, field tech) is authorized for INSPECT, but NOT REDUCE_LOAD
        action = ProposedAction(
            action_id="act_010",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Unscheduled load change by field technician",
            priority="MEDIUM",
            parameters={"reduction_kw": 20.0},
        )
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-002",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_marcus_act",
        )
        result = verify_personnel_authority(action, self.registry, self.test_now)
        self.assertTrue(result.is_authenticated)  # Identity authenticated
        self.assertFalse(result.is_authorized)     # Action scope denied
        self.assertEqual(result.status_code, "UNAUTHORIZED_ACTION")
        self.assertIn("outside permitted actions", result.failure_reason or "")

    def test_unauthorized_target_rejected(self) -> None:
        """Authenticated personnel targeting an unpermitted component must be denied."""
        # PERS-001 has permitted targets: load_1, battery_1, none (NOT critical_load)
        action = ProposedAction(
            action_id="act_011",
            action_type="REDUCE_LOAD",
            target="critical_load",
            reason="Curtailing critical facility without authorization",
            priority="HIGH",
            parameters={"reduction_kw": 50.0},
        )
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_target_test",
        )
        result = verify_personnel_authority(action, self.registry, self.test_now)
        self.assertTrue(result.is_authenticated)
        self.assertFalse(result.is_authorized)
        self.assertEqual(result.status_code, "UNAUTHORIZED_TARGET")
        self.assertIn("outside permitted targets", result.failure_reason or "")

    def test_priority_limit_exceeded_rejected(self) -> None:
        """Action priority exceeding the personnel's ceiling must be denied."""
        # PERS-002 has max_priority="MEDIUM", attempts HIGH
        action = ProposedAction(
            action_id="act_012",
            action_type="INSPECT",
            target="battery_1",
            reason="Urgent priority inspection",
            priority="HIGH",
        )
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-002",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_prio_test",
        )
        result = verify_personnel_authority(action, self.registry, self.test_now)
        self.assertTrue(result.is_authenticated)
        self.assertFalse(result.is_authorized)
        self.assertEqual(result.status_code, "PRIORITY_EXCEEDED")
        self.assertIn("exceeds maximum authorized priority", result.failure_reason or "")

    def test_parameter_limit_load_reduction_exceeded(self) -> None:
        """Load reduction exceeding personnel limit must be denied."""
        # PERS-001 max_load_reduction_kw is 250.0 kW; attempts 350.0 kW
        action = ProposedAction(
            action_id="act_013",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Excessive curtailment",
            priority="HIGH",
            parameters={"reduction_kw": 350.0},
        )
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_param_limit",
        )
        result = verify_personnel_authority(action, self.registry, self.test_now)
        self.assertTrue(result.is_authenticated)
        self.assertFalse(result.is_authorized)
        self.assertEqual(result.status_code, "PARAMETER_EXCEEDED")
        self.assertIn("exceeds authorized limit", result.failure_reason or "")

    def test_parameter_limit_non_positive_rejected(self) -> None:
        """Negative or zero load reduction values must be rejected."""
        action = ProposedAction(
            action_id="act_014",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Negative curtailment",
            priority="MEDIUM",
            parameters={"reduction_kw": -25.0},
        )
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_neg_kw",
        )
        result = verify_personnel_authority(action, self.registry, self.test_now)
        self.assertTrue(result.is_authenticated)
        self.assertFalse(result.is_authorized)
        self.assertEqual(result.status_code, "PARAMETER_EXCEEDED")
        self.assertIn("must be positive", result.failure_reason or "")

    def test_battery_isolation_disconnection_authority(self) -> None:
        """Disconnection/isolation requires explicit allow_component_disconnection."""
        # PERS-003 (Aria Patel, engineer) has allow_component_disconnection=False
        action = ProposedAction(
            action_id="act_015",
            action_type="ISOLATE_BATTERY",
            target="battery_1",
            reason="Battery maintenance isolation",
            priority="MEDIUM",
        )
        # Even if permitted_actions included it, parameter limits prohibit disconnection
        self.registry.update_permissions(
            "PERS-003",
            permitted_actions={"ISOLATE_BATTERY", "INSPECT"},
        )
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-003",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_disc_1",
        )
        result = verify_personnel_authority(action, self.registry, self.test_now)
        self.assertTrue(result.is_authenticated)
        self.assertFalse(result.is_authorized)
        self.assertEqual(result.status_code, "PARAMETER_EXCEEDED")
        self.assertIn("disconnection/isolation is not authorized", result.failure_reason or "")

    # ── Dual-Authorization / Co-Approval Tests ────────────────────────────────

    def test_missing_co_approval_rejected(self) -> None:
        """Actions requiring dual authorization must be blocked without a co-signer."""
        # PERS-004 (Silas Vance) requires co-approval for SHUTDOWN_LOAD
        action = ProposedAction(
            action_id="act_016",
            action_type="SHUTDOWN_LOAD",
            target="load_1",
            reason="Emergency shutdown without co-signer",
            priority="HIGH",
        )
        # Solo signature by Silas Vance
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-004",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_solo_co",
        )
        result = verify_personnel_authority(action, self.registry, self.test_now)
        self.assertTrue(result.is_authenticated)
        self.assertFalse(result.is_authorized)
        self.assertEqual(result.status_code, "MISSING_CO_APPROVAL")
        self.assertIn("requires dual-authorization", result.failure_reason or "")

    def test_self_co_approval_rejected(self) -> None:
        """Personnel cannot act as their own co-signer."""
        action = ProposedAction(
            action_id="act_017",
            action_type="SHUTDOWN_LOAD",
            target="load_1",
            reason="Shutdown with self co-approval",
            priority="HIGH",
        )
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-004",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_self_co",
            co_signer_id="PERS-004",  # Self co-approval
        )
        result = verify_personnel_authority(action, self.registry, self.test_now)
        self.assertTrue(result.is_authenticated)
        self.assertFalse(result.is_authorized)
        self.assertEqual(result.status_code, "INVALID_CO_SIGNER")
        self.assertIn("cannot be identical", result.failure_reason or "")

    def test_invalid_or_revoked_co_signer_rejected(self) -> None:
        """Co-signer who is revoked or unrecognized must be rejected."""
        action = ProposedAction(
            action_id="act_018",
            action_type="SHUTDOWN_LOAD",
            target="load_1",
            reason="Shutdown with revoked co-signer",
            priority="HIGH",
        )
        # PERS-005 is revoked
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-004",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_rev_co",
            co_signer_id="PERS-005",
        )
        result = verify_personnel_authority(action, self.registry, self.test_now)
        self.assertTrue(result.is_authenticated)
        self.assertFalse(result.is_authorized)
        self.assertEqual(result.status_code, "INVALID_CO_SIGNER")
        self.assertIn("inactive or revoked", result.failure_reason or "")

    def test_valid_co_approval_success(self) -> None:
        """Valid dual-authorization by two active authorized personnel succeeds."""
        action = ProposedAction(
            action_id="act_019",
            action_type="SHUTDOWN_LOAD",
            target="load_1",
            reason="Authorized dual-operator shutdown",
            priority="HIGH",
        )
        # Silas Vance (PERS-004) co-approved by Elena Vance (PERS-001)
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-004",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_dual_ok",
            co_signer_id="PERS-001",
        )
        result = verify_personnel_authority(action, self.registry, self.test_now)
        self.assertTrue(result.is_authenticated)
        self.assertTrue(result.is_authorized)
        self.assertEqual(result.status_code, "AUTH_OK")
        self.assertEqual(result.personnel_id, "PERS-004")
        self.assertEqual(result.co_signer_id, "PERS-001")

    def test_co_signer_lacking_action_authority_rejected(self) -> None:
        """Co-signer who lacks authority for the required action must be rejected."""
        action = ProposedAction(
            action_id="act_019b",
            action_type="SHUTDOWN_LOAD",
            target="load_1",
            reason="Shutdown with unauthorized co-signer",
            priority="HIGH",
        )
        # Marcus Thorne (PERS-002) is a field tech without SHUTDOWN_LOAD permission
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-004",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_marcus_co",
            co_signer_id="PERS-002",
        )
        result = verify_personnel_authority(action, self.registry, self.test_now)
        self.assertTrue(result.is_authenticated)
        self.assertFalse(result.is_authorized)
        self.assertEqual(result.status_code, "INVALID_CO_SIGNER")
        self.assertIn("not authorized for action type", result.failure_reason or "")

    # ── Experience / Designation Security Principle Tests ────────────────────

    def test_experience_or_designation_alone_does_not_grant_authority(self) -> None:
        """
        Security requirement: High experience and executive job title alone
        must NEVER grant operational authority. Explicit permissions are required.
        """
        # Register a high-experience executive with read-only permissions
        exec_record = PersonnelRecord(
            personnel_id="PERS-999-EXEC",
            name="Arthur Pendelton",
            designation="Executive Vice President of Grid Systems",
            department="Executive Management",
            experience_years=40,  # 40 years of experience
            is_active=True,
            valid_from=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            valid_to=datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
            permitted_actions={"INSPECT", "LOG_WARNING"},  # Explicitly read-only
            permitted_targets={"none"},
            parameter_limits=ParameterLimits(),
            max_priority="LOW",
            credential_ref="cred_exec_999",
            issuer="AEGIS_GRID_CA",
        )
        self.registry.register_personnel(exec_record, private_key="exec_secret_key_999")

        # Executive attempts a critical REDUCE_LOAD command
        action = ProposedAction(
            action_id="act_020",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Executive override attempt",
            priority="HIGH",
            parameters={"reduction_kw": 100.0},
        )
        action.authorization_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-999-EXEC",
            action=action,
            issued_at=self.test_now.isoformat(),
            nonce="nonce_exec_1",
        )

        result = verify_personnel_authority(action, self.registry, self.test_now)
        # Authentication passes (signature is valid, active, within validity window)
        self.assertTrue(result.is_authenticated)
        # BUT Authorization MUST fail: experience/title cannot bypass permitted_actions
        self.assertFalse(result.is_authorized)
        self.assertEqual(result.status_code, "UNAUTHORIZED_ACTION")
        self.assertEqual(result.personnel_id, "PERS-999-EXEC")
        self.assertEqual(result.role, "Executive Vice President of Grid Systems")

    # ── Backward Compatibility Tests ─────────────────────────────────────────

    def test_backward_compatibility_claimed_authorization_preserved(self) -> None:
        """Existing actions with claimed_authorization remain fully supported."""
        action = ProposedAction(
            action_id="act_legacy_001",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="Legacy workflow proposal",
            priority="LOW",
            claimed_authorization="rep_10:00",
        )
        self.assertEqual(action.claimed_authorization, "rep_10:00")
        self.assertIsNone(action.authorization_evidence)
        self.assertTrue(action.is_digest_valid())


if __name__ == "__main__":
    unittest.main()
