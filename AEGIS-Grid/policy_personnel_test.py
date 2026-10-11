"""
policy_personnel_test.py
Focused test suite for AEGIS GRID Personnel Authority Registry integration into aegis/policy.py.

Tests cover:
1. Valid authorized actions
2. Unauthorized actions (out-of-scope actions, targets, revoked, expired)
3. Forged and unauthenticated credentials (signature tampering, token strings, payload tampering)
4. Privilege escalation attempts (priority, parameter limits, missing or invalid co-approval)
5. Physically unsafe actions (battery isolation on normal telemetry, critical load shutdowns, invalid setpoints)
6. Diagnostic report provenance and monitoring compatibility
"""

import unittest
from datetime import datetime, timezone

from agents.schemas import ProposedAction, AuthorizationEvidence
from aegis.policy import verify_policy, PolicyResult
from aegis.personnel import (
    PersonnelRecord,
    ParameterLimits,
    PersonnelAuthorityRegistry,
    build_default_registry,
)


class PolicyPersonnelIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.registry = build_default_registry()
        self.signing_auth = self.registry.signing_authority
        self.fixed_now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

    # =========================================================================
    # 1. VALID AUTHORIZED ACTIONS
    # =========================================================================

    def test_valid_dispatcher_load_reduction_allowed(self):
        """Lead Dispatcher (PERS-001) in-scope REDUCE_LOAD is allowed."""
        action = ProposedAction(
            action_id="act_disp_01",
            run_id="run_disp_01",
            session_id="sess_01",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Peak shaving dispatch",
            priority="MEDIUM",
            parameters={"reduction_kw": 150.0},
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_disp_01",
        )
        action.authorization_evidence = evidence

        result = verify_policy(
            action,
            personnel_registry=self.registry,
            now=self.fixed_now,
        )
        self.assertEqual(result.decision, "allow")
        self.assertEqual(result.matched_rule_id, "rule_007_personnel_authorized")
        self.assertIn("PERS-001", result.reason)

    def test_valid_supervisor_battery_isolation_allowed_with_anomaly_telemetry(self):
        """Supervisor (PERS-004) ISOLATE_BATTERY is allowed when telemetry corroborates anomaly."""
        action = ProposedAction(
            action_id="act_sup_01",
            run_id="run_sup_01",
            session_id="sess_01",
            action_type="ISOLATE_BATTERY",
            target="battery_1",
            reason="Emergency cell protection",
            priority="HIGH",
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-004",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_sup_01",
        )
        action.authorization_evidence = evidence

        # Microgrid telemetry corroborating overheat condition
        context = {
            "battery_temperature_c": 68.5,
            "report_status": "ANOMALY",
            "report_severity": "HIGH",
        }

        result = verify_policy(
            action,
            context=context,
            personnel_registry=self.registry,
            now=self.fixed_now,
        )
        self.assertEqual(result.decision, "allow")
        self.assertEqual(result.matched_rule_id, "rule_007_personnel_authorized")

    def test_valid_supervisor_load_shutdown_with_co_approval_allowed(self):
        """Supervisor (PERS-004) SHUTDOWN_LOAD with valid co-approval from PERS-001 is allowed."""
        action = ProposedAction(
            action_id="act_sup_02",
            run_id="run_sup_02",
            session_id="sess_01",
            action_type="SHUTDOWN_LOAD",
            target="load_1",
            reason="Substation feeder de-energization",
            priority="HIGH",
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-004",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_sup_02",
            co_signer_id="PERS-001",
        )
        action.authorization_evidence = evidence

        result = verify_policy(
            action,
            personnel_registry=self.registry,
            now=self.fixed_now,
        )
        self.assertEqual(result.decision, "allow")
        self.assertEqual(result.matched_rule_id, "rule_007_personnel_authorized")

    # =========================================================================
    # 2. UNAUTHORIZED ACTIONS (OUT OF SCOPE / ROLE RESTRICTIONS)
    # =========================================================================

    def test_unauthorized_action_type_blocked(self):
        """Field Tech (PERS-002) attempting REDUCE_LOAD is blocked as out of scope."""
        action = ProposedAction(
            action_id="act_tech_01",
            run_id="run_tech_01",
            session_id="sess_01",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Field tech load adjustment",
            priority="LOW",
            parameters={"reduction_kw": 50.0},
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-002",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_tech_01",
        )
        action.authorization_evidence = evidence

        result = verify_policy(
            action,
            personnel_registry=self.registry,
            now=self.fixed_now,
        )
        self.assertEqual(result.decision, "block")
        self.assertEqual(result.matched_rule_id, "rule_000_unauthorized_personnel")
        self.assertIn("UNAUTHORIZED_ACTION", result.reason)

    def test_unauthorized_target_blocked(self):
        """Lead Dispatcher (PERS-001) attempting action on unauthorized target is blocked."""
        action = ProposedAction(
            action_id="act_disp_02",
            run_id="run_disp_02",
            session_id="sess_01",
            action_type="REDUCE_LOAD",
            target="critical_load",
            reason="Dispatcher load shed on hospital feeder",
            priority="MEDIUM",
            parameters={"reduction_kw": 100.0},
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_disp_02",
        )
        action.authorization_evidence = evidence

        result = verify_policy(
            action,
            personnel_registry=self.registry,
            now=self.fixed_now,
        )
        self.assertEqual(result.decision, "block")
        self.assertEqual(result.matched_rule_id, "rule_000_unauthorized_personnel")
        self.assertIn("UNAUTHORIZED_TARGET", result.reason)

    def test_revoked_personnel_credential_blocked(self):
        """Revoked contractor (PERS-005) attempting INSPECT is blocked fail-closed."""
        action = ProposedAction(
            action_id="act_revoked_01",
            run_id="run_rev_01",
            session_id="sess_01",
            action_type="INSPECT",
            target="battery_1",
            reason="Contractor routine check",
            priority="LOW",
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-005",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_rev_01",
        )
        action.authorization_evidence = evidence

        result = verify_policy(
            action,
            personnel_registry=self.registry,
            now=self.fixed_now,
        )
        self.assertEqual(result.decision, "block")
        self.assertEqual(result.matched_rule_id, "rule_000_unauthorized_personnel")
        self.assertIn("REVOKED_CREDENTIAL", result.reason)

    def test_expired_personnel_credential_blocked(self):
        """Credential evaluated after personnel expiration date is blocked fail-closed."""
        action = ProposedAction(
            action_id="act_exp_01",
            run_id="run_exp_01",
            session_id="sess_01",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="Routine check",
            priority="LOW",
        )
        # PERS-003 expires 2026-12-31. Evaluate in 2027.
        future_now = datetime(2027, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-003",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_exp_01",
        )
        action.authorization_evidence = evidence

        result = verify_policy(
            action,
            personnel_registry=self.registry,
            now=future_now,
        )
        self.assertEqual(result.decision, "block")
        self.assertEqual(result.matched_rule_id, "rule_000_unauthorized_personnel")
        self.assertIn("EXPIRED_CREDENTIAL", result.reason)

    # =========================================================================
    # 3. FORGED CREDENTIALS AND STRING-PATTERN SPOOFING
    # =========================================================================

    def test_claimed_personnel_id_string_without_evidence_blocked(self):
        """Claiming 'PERS-001' in claimed_authorization without cryptographic evidence is blocked."""
        action = ProposedAction(
            action_id="act_spoof_01",
            run_id="run_spoof_01",
            session_id="sess_01",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Spoofed operator override",
            priority="MEDIUM",
            claimed_authorization="PERS-001",
            parameters={"reduction_kw": 100.0},
        )
        result = verify_policy(action)
        self.assertEqual(result.decision, "block")
        self.assertEqual(result.matched_rule_id, "rule_000_unauthenticated_personnel")

    def test_claimed_cred_pers_string_without_evidence_blocked(self):
        """Claiming 'cred_pers_12345' in claimed_authorization without cryptographic evidence is blocked."""
        action = ProposedAction(
            action_id="act_spoof_02",
            run_id="run_spoof_02",
            session_id="sess_01",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Spoofed token string",
            priority="MEDIUM",
            claimed_authorization="cred_pers_disp_99999",
            parameters={"reduction_kw": 100.0},
        )
        result = verify_policy(action)
        self.assertEqual(result.decision, "block")
        self.assertEqual(result.matched_rule_id, "rule_000_unauthenticated_personnel")

    def test_forged_hmac_signature_blocked(self):
        """Forged or tampered HMAC signature is detected and blocked fail-closed."""
        action = ProposedAction(
            action_id="act_forge_sig",
            run_id="run_forge_01",
            session_id="sess_01",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Forged authorization test",
            priority="MEDIUM",
            parameters={"reduction_kw": 100.0},
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_forge_01",
        )
        # Tamper the signature bytes
        evidence.signature = "f" * 64
        action.authorization_evidence = evidence

        result = verify_policy(
            action,
            personnel_registry=self.registry,
            now=self.fixed_now,
        )
        self.assertEqual(result.decision, "block")
        self.assertEqual(result.matched_rule_id, "rule_000_unauthorized_personnel")
        self.assertIn("INVALID_SIGNATURE", result.reason)

    def test_unknown_personnel_id_blocked(self):
        """Unregistered personnel identifier is rejected fail-closed."""
        action = ProposedAction(
            action_id="act_unknown_pers",
            run_id="run_unk_01",
            session_id="sess_01",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Unknown attacker ID",
            priority="MEDIUM",
            parameters={"reduction_kw": 100.0},
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_unk_01",
        )
        # Mutate to unknown ID
        evidence.personnel_id = "PERS-999"
        action.authorization_evidence = evidence

        result = verify_policy(
            action,
            personnel_registry=self.registry,
            now=self.fixed_now,
        )
        self.assertEqual(result.decision, "block")
        self.assertEqual(result.matched_rule_id, "rule_000_unauthorized_personnel")
        self.assertIn("UNKNOWN_PERSONNEL", result.reason)

    def test_action_payload_tampering_post_signing_blocked(self):
        """Mutating action target post-signing is detected by digest check and blocked."""
        action = ProposedAction(
            action_id="act_tamper_post",
            run_id="run_tamper_01",
            session_id="sess_01",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Signed load reduction",
            priority="MEDIUM",
            parameters={"reduction_kw": 100.0},
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_tamper_01",
        )
        action.authorization_evidence = evidence

        # Adversary modifies action target post-signing
        action.target = "battery_1"

        result = verify_policy(
            action,
            personnel_registry=self.registry,
            now=self.fixed_now,
        )
        self.assertEqual(result.decision, "block")
        self.assertEqual(result.matched_rule_id, "rule_000_unauthorized_personnel")
        self.assertIn("TAMPERED_ACTION", result.reason)

    def test_severe_action_missing_authorization_blocked(self):
        """Severe action missing both claimed_authorization and authorization_evidence is blocked."""
        action = ProposedAction(
            action_id="act_missing_both",
            run_id="run_miss_01",
            session_id="sess_01",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Unauthenticated load reduction",
            priority="HIGH",
            parameters={"reduction_kw": 100.0},
            claimed_authorization=None,
            authorization_evidence=None,
        )
        result = verify_policy(action)
        self.assertEqual(result.decision, "block")
        self.assertEqual(result.matched_rule_id, "rule_004")

    # =========================================================================
    # 4. PRIVILEGE ESCALATION ATTEMPTS
    # =========================================================================

    def test_priority_escalation_blocked(self):
        """Field Tech (PERS-002, max priority LOW) attempting HIGH priority is blocked."""
        action = ProposedAction(
            action_id="act_prio_esc",
            run_id="run_prio_01",
            session_id="sess_01",
            action_type="INSPECT",
            target="battery_1",
            reason="Escalated inspection",
            priority="HIGH",
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-002",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_prio_01",
        )
        action.authorization_evidence = evidence

        result = verify_policy(
            action,
            personnel_registry=self.registry,
            now=self.fixed_now,
        )
        self.assertEqual(result.decision, "block")
        self.assertEqual(result.matched_rule_id, "rule_000_unauthorized_personnel")
        self.assertIn("PRIORITY_EXCEEDED", result.reason)

    def test_parameter_limit_escalation_blocked(self):
        """Lead Dispatcher (PERS-001, limit 250 kW) attempting 350 kW reduction is blocked."""
        action = ProposedAction(
            action_id="act_param_esc",
            run_id="run_param_01",
            session_id="sess_01",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Excessive load reduction",
            priority="MEDIUM",
            parameters={"reduction_kw": 350.0},
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_param_01",
        )
        action.authorization_evidence = evidence

        result = verify_policy(
            action,
            personnel_registry=self.registry,
            now=self.fixed_now,
        )
        self.assertEqual(result.decision, "block")
        self.assertEqual(result.matched_rule_id, "rule_000_unauthorized_personnel")
        self.assertIn("PARAMETER_EXCEEDED", result.reason)

    def test_missing_co_approval_blocked(self):
        """Supervisor (PERS-004) attempting SHUTDOWN_LOAD without required co-approval is blocked."""
        action = ProposedAction(
            action_id="act_co_missing",
            run_id="run_co_01",
            session_id="sess_01",
            action_type="SHUTDOWN_LOAD",
            target="load_1",
            reason="Unilateral load shutdown attempt",
            priority="HIGH",
        )
        # Solo signature by Silas Vance without co-signer
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-004",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_co_01",
            co_signer_id=None,
        )
        action.authorization_evidence = evidence

        result = verify_policy(
            action,
            personnel_registry=self.registry,
            now=self.fixed_now,
        )
        self.assertEqual(result.decision, "block")
        self.assertEqual(result.matched_rule_id, "rule_000_unauthorized_personnel")
        self.assertIn("MISSING_CO_APPROVAL", result.reason)

    def test_co_signer_lacking_authority_blocked(self):
        """Supervisor (PERS-004) with co-signer lacking SHUTDOWN_LOAD authority is blocked."""
        action = ProposedAction(
            action_id="act_co_unauth",
            run_id="run_co_02",
            session_id="sess_01",
            action_type="SHUTDOWN_LOAD",
            target="load_1",
            reason="Load shutdown with unqualified co-signer",
            priority="HIGH",
        )
        # PERS-002 (Marcus Thorne) is a field tech without SHUTDOWN_LOAD authority
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-004",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_co_02",
            co_signer_id="PERS-002",
        )
        action.authorization_evidence = evidence

        result = verify_policy(
            action,
            personnel_registry=self.registry,
            now=self.fixed_now,
        )
        self.assertEqual(result.decision, "block")
        self.assertEqual(result.matched_rule_id, "rule_000_unauthorized_personnel")
        self.assertIn("INVALID_CO_SIGNER", result.reason)

    # =========================================================================
    # 5. PHYSICALLY UNSAFE ACTIONS (DECOUPLING CREDENTIALS FROM ELECTRICAL SAFETY)
    # =========================================================================

    def test_valid_supervisor_battery_isolation_blocked_on_normal_telemetry(self):
        """Valid supervisor credentials CANNOT force battery isolation when telemetry is normal."""
        action = ProposedAction(
            action_id="act_phys_unsafe_01",
            run_id="run_phys_01",
            session_id="sess_01",
            action_type="ISOLATE_BATTERY",
            target="battery_1",
            reason="Unwarranted battery isolation",
            priority="HIGH",
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-004",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_phys_01",
        )
        action.authorization_evidence = evidence

        # Telemetry is completely healthy (temperature 32 C, report status NORMAL)
        context = {
            "battery_temperature_c": 32.0,
            "report_status": "NORMAL",
            "report_severity": "NONE",
        }

        result = verify_policy(
            action,
            context=context,
            personnel_registry=self.registry,
            now=self.fixed_now,
        )
        # Crucial test: Authorization is separate from physical safety!
        self.assertEqual(result.decision, "block")
        self.assertEqual(result.matched_rule_id, "rule_002c")
        self.assertIn("unsupported by microgrid telemetry", result.reason)

    def test_valid_co_approved_critical_load_shutdown_escalates_to_human_approval(self):
        """Valid co-approved credentials CANNOT bypass critical-load human approval requirement."""
        action = ProposedAction(
            action_id="act_phys_unsafe_02",
            run_id="run_phys_02",
            session_id="sess_01",
            action_type="SHUTDOWN_LOAD",
            target="critical_load",
            reason="Critical hospital feeder shutdown",
            priority="HIGH",
        )
        # Register a second senior supervisor co-signer authorized for critical_load
        pers_co = PersonnelRecord(
            personnel_id="PERS-006",
            name="Clara Hughes",
            designation="Operations Director",
            department="Grid Operations",
            experience_years=22,
            is_active=True,
            valid_from=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            valid_to=datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
            permitted_actions={"SHUTDOWN_LOAD"},
            permitted_targets={"critical_load", "load_1"},
            parameter_limits=ParameterLimits(),
            max_priority="HIGH",
            credential_ref="cred_pers_006_v1",
            issuer="AEGIS_GRID_CA",
        )
        self.registry.register_personnel(pers_co)

        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-004",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_phys_02",
            co_signer_id="PERS-006",
        )
        action.authorization_evidence = evidence

        result = verify_policy(
            action,
            personnel_registry=self.registry,
            now=self.fixed_now,
        )
        # Electrical safety: Critical-load shutdown ALWAYS requires human review
        self.assertEqual(result.decision, "human_approval")
        self.assertEqual(result.matched_rule_id, "rule_001")
        self.assertIn("forbids auto-shutdown of critical load", result.reason)

    def test_valid_dispatcher_negative_load_reduction_blocked(self):
        """Negative load reduction parameter violates grid physics and is blocked."""
        # Test physical parameter limit on diagnostic action
        action = ProposedAction(
            action_id="act_phys_unsafe_03",
            run_id="run_phys_03",
            session_id="sess_01",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Negative setpoint injection",
            priority="MEDIUM",
            parameters={"reduction_kw": -25.0},
            claimed_authorization="rep_10:00",
        )
        result = verify_policy(action)
        self.assertEqual(result.decision, "block")
        self.assertEqual(result.matched_rule_id, "rule_006_physical_parameter_limits")

    def test_valid_dispatcher_excessive_feeder_load_reduction_blocked(self):
        """Load reduction exceeding physical feeder capacity (> 1000 kW) is blocked."""
        action = ProposedAction(
            action_id="act_phys_unsafe_04",
            run_id="run_phys_04",
            session_id="sess_01",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Feeder capacity violation",
            priority="MEDIUM",
            parameters={"reduction_kw": 1200.0},
            claimed_authorization="rep_10:00",
        )
        result = verify_policy(action)
        self.assertEqual(result.decision, "block")
        self.assertEqual(result.matched_rule_id, "rule_006_physical_parameter_limits")

    def test_battery_isolation_on_non_battery_target_blocked(self):
        """Battery isolation proposed on load_1 is blocked regardless of credentials."""
        action = ProposedAction(
            action_id="act_phys_unsafe_05",
            run_id="run_phys_05",
            session_id="sess_01",
            action_type="ISOLATE_BATTERY",
            target="load_1",
            reason="Target mismatch isolation",
            priority="HIGH",
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-004",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_phys_05",
        )
        action.authorization_evidence = evidence

        result = verify_policy(
            action,
            personnel_registry=self.registry,
            now=self.fixed_now,
        )
        self.assertEqual(result.decision, "block")
        self.assertEqual(result.matched_rule_id, "rule_002a")

    # =========================================================================
    # 6. COMPATIBILITY WITH DIAGNOSTIC-REPORT WORKFLOWS
    # =========================================================================

    def test_diagnostic_report_routine_maintenance_allowed(self):
        """Existing automated workflow: MAINTAIN_STATUS with report ID is allowed."""
        action = ProposedAction(
            action_id="act_diag_01",
            run_id="run_diag_01",
            session_id="sess_01",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="System normal",
            priority="LOW",
            claimed_authorization="rep_10:00",
        )
        result = verify_policy(action)
        self.assertEqual(result.decision, "allow")
        self.assertEqual(result.matched_rule_id, "rule_003")

    def test_diagnostic_report_emergency_isolation_allowed(self):
        """Existing automated workflow: emergency battery isolation during anomaly is allowed."""
        action = ProposedAction(
            action_id="act_diag_02",
            run_id="run_diag_02",
            session_id="sess_01",
            action_type="ISOLATE_BATTERY",
            target="battery_1",
            reason="Thermal runaway detected by monitoring agent",
            priority="HIGH",
            claimed_authorization="rep_02:21",
        )
        context = {
            "battery_temperature_c": 92.5,
            "report_status": "ANOMALY",
            "report_severity": "CRITICAL",
        }
        result = verify_policy(action, context=context)
        self.assertEqual(result.decision, "allow")
        self.assertEqual(result.matched_rule_id, "rule_002_emergency")


if __name__ == "__main__":
    unittest.main()
