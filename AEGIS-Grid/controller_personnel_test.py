"""
controller_personnel_test.py
Focused test suite for AEGIS GRID End-to-End Personnel Authorization Enforcement.

Verifies actual final controller decisions (make_decision and workflow execution),
guaranteeing:
1. Valid personnel authorization receives ALLOW.
2. Forged evidence, tampered actions, and invalid signatures receive BLOCK.
3. Privilege escalation (unauthorized action, target, priority, parameters) receives BLOCK.
4. Missing co-approval or invalid co-signer receives BLOCK.
5. Revoked and expired credentials receive BLOCK.
6. Missing provenance / unauthenticated personnel claims receive BLOCK.
7. Physical safety rules (policy BLOCK) cannot be overridden by valid credentials.
8. Telemetry replay attacks cannot be overridden by valid credentials.
9. Mandatory HUMAN_APPROVAL outcomes (e.g. critical load shutdown) cannot be overridden to ALLOW.
10. Gate 3 independently blocks invalid personnel credentials even if policy is permissive.
11. Diagnostic-report provenance and automated workflows remain fully functional and protected.
12. End-to-end workflow graph execution with personnel credentials succeeds without SQLite report-consumption corruption.
"""

import unittest
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from agents.schemas import ProposedAction, AuthorizationEvidence, MonitoringReport
from aegis.policy import verify_policy, PolicyResult
from aegis.provenance import verify_provenance, ProvenanceResult
from aegis.behaviour import BehaviourResult, reset_behaviour_history, get_recent_history
from aegis.risk import evaluate_risk, RiskResult
from aegis.controller import make_decision, FinalDecision
from aegis.personnel import (
    PersonnelRecord,
    ParameterLimits,
    PersonnelAuthorityRegistry,
    SimulatedSigningAuthority,
    build_default_registry,
    verify_personnel_authority,
)
from database.models import ReplayCheckResult
from database.sqlite import (
    init_db,
    consume_personnel_credential,
    is_personnel_credential_consumed,
)
import workflow.graph as graph


class ControllerPersonnelEnforcementTest(unittest.TestCase):
    """Verifies final controller decisions for all personnel authorization scenarios."""

    def setUp(self):
        reset_behaviour_history()
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_file.name
        self.temp_file.close()
        init_db(self.db_path)
        self.registry = build_default_registry()
        self.registry.db_path = self.db_path
        self.signing_auth = self.registry.signing_authority
        self.fixed_now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        self.benign_behaviour = BehaviourResult(flagged=False, score=0.0)
        self.sqlite_path_patcher = patch("config.SQLITE_PATH", self.db_path)
        self.sqlite_path_patcher.start()

    def tearDown(self):
        self.sqlite_path_patcher.stop()
        try:
            Path(self.db_path).unlink(missing_ok=True)
        except Exception:
            pass

    # ── Helper for full AEGIS pipeline evaluation ────────────────────────────
    def _evaluate_pipeline(self, action, context=None, replay_detected=False, behaviour=None, auto_consume=True):
        """Runs action through verify_policy, verify_provenance, evaluate_risk, make_decision."""
        ctx = context or {}
        policy_res = verify_policy(
            action,
            context=ctx,
            personnel_registry=self.registry,
            now=self.fixed_now,
        )
        prov_res = verify_provenance(
            action,
            session_id=getattr(action, "session_id", "test_sess"),
            personnel_registry=self.registry,
            now=self.fixed_now,
        )
        beh_res = behaviour or self.benign_behaviour
        replay_res = ReplayCheckResult(
            detected=replay_detected,
            reason="Telemetry replay detected" if replay_detected else "Fresh telemetry",
            fingerprint="fp_test_01",
            observation_timestamp="12:00",
        )
        risk_res = evaluate_risk(
            policy_res=policy_res,
            prov_res=prov_res,
            behav_res=beh_res,
            replay_result=replay_res,
        )
        final_decision = make_decision(
            action=action,
            policy_res=policy_res,
            prov_res=prov_res,
            behav_res=beh_res,
            risk_res=risk_res,
        )
        if auto_consume and final_decision.final_decision == "allow":
            evidence = getattr(action, "authorization_evidence", None)
            if evidence and evidence.token_type == "PERSONNEL_CREDENTIAL" and evidence.nonce and evidence.personnel_id:
                consume_personnel_credential(
                    personnel_id=evidence.personnel_id,
                    nonce=evidence.nonce,
                    action_id=action.action_id,
                    session_id=getattr(action, "session_id", "test_sess"),
                    run_id=getattr(action, "run_id", "test_run"),
                    action_digest=getattr(action, "action_digest", ""),
                    co_signer_id=evidence.co_signer_id,
                    db_path=self.db_path,
                )
        return policy_res, prov_res, risk_res, final_decision

    # =========================================================================
    # 1. VALID PERSONNEL AUTHORIZATION -> ALLOW
    # =========================================================================

    def test_valid_authorized_personnel_action_receives_allow(self):
        """Lead Dispatcher (PERS-001) in-scope REDUCE_LOAD receives ALLOW."""
        action = ProposedAction(
            action_id="act_valid_01",
            run_id="run_valid_01",
            session_id="sess_valid_01",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Scheduled peak shaving",
            priority="MEDIUM",
            parameters={"reduction_kw": 150.0},
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_val_01",
        )
        action.authorization_evidence = evidence

        policy_res, prov_res, risk_res, decision = self._evaluate_pipeline(action)

        self.assertEqual(policy_res.decision, "allow")
        self.assertTrue(prov_res.verified)
        self.assertEqual(prov_res.auth_type, "personnel")
        self.assertEqual(prov_res.personnel_id, "PERS-001")
        self.assertEqual(decision.final_decision, "allow")
        self.assertIn("approved", decision.reason.lower())

    def test_valid_maintenance_personnel_action_receives_allow(self):
        """Technician (PERS-002) in-scope INSPECT on battery_1 receives ALLOW."""
        action = ProposedAction(
            action_id="act_valid_02",
            run_id="run_valid_02",
            session_id="sess_valid_02",
            action_type="INSPECT",
            target="battery_1",
            reason="Routine cell temperature inspection",
            priority="LOW",
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-002",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_val_02",
        )
        action.authorization_evidence = evidence

        policy_res, prov_res, risk_res, decision = self._evaluate_pipeline(action)

        self.assertEqual(policy_res.decision, "allow")
        self.assertTrue(prov_res.verified)
        self.assertEqual(decision.final_decision, "allow")

    # =========================================================================
    # 2. FORGED EVIDENCE & SIGNATURE TAMPERING -> BLOCK
    # =========================================================================

    def test_forged_cryptographic_signature_receives_block(self):
        """Attacker modifies HMAC signature: controller must return BLOCK, not human_approval."""
        action = ProposedAction(
            action_id="act_forge_01",
            run_id="run_forge_01",
            session_id="sess_forge_01",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Attacker forged dispatch",
            priority="MEDIUM",
            parameters={"reduction_kw": 100.0},
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_forge_01",
        )
        # Corrupt the cryptographic signature
        evidence.signature = "a" * 64
        action.authorization_evidence = evidence

        policy_res, prov_res, risk_res, decision = self._evaluate_pipeline(action)

        self.assertEqual(policy_res.decision, "block")
        self.assertFalse(prov_res.verified)
        self.assertEqual(prov_res.status, "invalid_signature")
        self.assertEqual(decision.final_decision, "block")
        self.assertTrue("Policy Override" in decision.reason or "Provenance Denied" in decision.reason)

    def test_forged_evidence_with_arbitrary_key_receives_block(self):
        """Attacker signs with an arbitrary untrusted key: controller returns BLOCK."""
        action = ProposedAction(
            action_id="act_forge_02",
            run_id="run_forge_02",
            session_id="sess_forge_02",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="Unauthenticated status claim",
            priority="LOW",
        )
        evidence = AuthorizationEvidence(
            token_type="PERSONNEL_CREDENTIAL",
            personnel_id="PERS-001",
            signature="deadbeefcafebabe0123456789abcdef",
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_fake",
        )
        action.authorization_evidence = evidence

        policy_res, prov_res, risk_res, decision = self._evaluate_pipeline(action)

        self.assertFalse(prov_res.verified)
        self.assertEqual(decision.final_decision, "block")

    # =========================================================================
    # 3. ACTION TAMPERING (DIGEST MISMATCH) -> BLOCK
    # =========================================================================

    def test_tampered_action_parameters_receives_block(self):
        """Action signed for 50kW reduction but modified in-flight to 200kW receives BLOCK."""
        action = ProposedAction(
            action_id="act_tamper_01",
            run_id="run_tamper_01",
            session_id="sess_tamper_01",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Original authorization for 50 kW",
            priority="LOW",
            parameters={"reduction_kw": 50.0},
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_tamper_01",
        )
        action.authorization_evidence = evidence

        # Adversary tampers with parameters after signature generation
        action.parameters["reduction_kw"] = 200.0

        policy_res, prov_res, risk_res, decision = self._evaluate_pipeline(action)

        self.assertFalse(prov_res.verified)
        self.assertEqual(prov_res.status, "action_digest_mismatch")
        self.assertEqual(decision.final_decision, "block")

    def test_tampered_action_type_receives_block(self):
        """Action signed for MAINTAIN_STATUS but modified in-flight to SHUTDOWN_LOAD receives BLOCK."""
        action = ProposedAction(
            action_id="act_tamper_02",
            run_id="run_tamper_02",
            session_id="sess_tamper_02",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="Original maintain status",
            priority="LOW",
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_tamper_02",
        )
        action.authorization_evidence = evidence

        # Adversary escalates action_type to severe action
        action.action_type = "SHUTDOWN_LOAD"
        action.target = "load_1"

        policy_res, prov_res, risk_res, decision = self._evaluate_pipeline(action)

        self.assertFalse(prov_res.verified)
        self.assertEqual(decision.final_decision, "block")

    # =========================================================================
    # 4. PRIVILEGE ESCALATION -> BLOCK
    # =========================================================================

    def test_privilege_escalation_unauthorized_action_type_receives_block(self):
        """PERS-002 (Technician) is not authorized for ISOLATE_BATTERY: receives BLOCK."""
        action = ProposedAction(
            action_id="act_esc_01",
            run_id="run_esc_01",
            session_id="sess_esc_01",
            action_type="ISOLATE_BATTERY",
            target="battery_1",
            reason="Technician attempting battery disconnection",
            priority="HIGH",
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-002",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_esc_01",
        )
        action.authorization_evidence = evidence

        policy_res, prov_res, risk_res, decision = self._evaluate_pipeline(action)

        self.assertEqual(policy_res.decision, "block")
        self.assertFalse(prov_res.verified)
        self.assertEqual(prov_res.status, "unauthorized_action")
        self.assertEqual(decision.final_decision, "block")

    def test_privilege_escalation_unauthorized_target_receives_block(self):
        """PERS-003 (Storage Engineer, permitted battery_1, load_1, none) attempting critical_load: receives BLOCK."""
        action = ProposedAction(
            action_id="act_esc_02",
            run_id="run_esc_02",
            session_id="sess_esc_02",
            action_type="REDUCE_LOAD",
            target="critical_load",
            reason="Storage engineer attempting unauthorized reduction on critical load",
            priority="MEDIUM",
            parameters={"reduction_kw": 25.0},
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-003",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_esc_02",
        )
        action.authorization_evidence = evidence

        policy_res, prov_res, risk_res, decision = self._evaluate_pipeline(action)

        self.assertEqual(policy_res.decision, "block")
        self.assertFalse(prov_res.verified)
        self.assertEqual(prov_res.status, "unauthorized_target")
        self.assertEqual(decision.final_decision, "block")

    def test_privilege_escalation_exceeded_priority_receives_block(self):
        """PERS-002 (Junior Field Tech, max priority MEDIUM) proposing HIGH priority: receives BLOCK."""
        action = ProposedAction(
            action_id="act_esc_03",
            run_id="run_esc_03",
            session_id="sess_esc_03",
            action_type="INSPECT",
            target="battery_1",
            reason="Junior technician escalates inspection to emergency HIGH priority",
            priority="HIGH",
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-002",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_esc_03",
        )
        action.authorization_evidence = evidence

        policy_res, prov_res, risk_res, decision = self._evaluate_pipeline(action)

        self.assertEqual(policy_res.decision, "block")
        self.assertFalse(prov_res.verified)
        self.assertEqual(prov_res.status, "priority_exceeded")
        self.assertEqual(decision.final_decision, "block")

    def test_privilege_escalation_exceeded_parameters_receives_block(self):
        """PERS-003 (max reduction 50 kW) proposing 150 kW: receives BLOCK."""
        action = ProposedAction(
            action_id="act_esc_04",
            run_id="run_esc_04",
            session_id="sess_esc_04",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Storage engineer proposes reduction exceeding authorized limit",
            priority="MEDIUM",
            parameters={"reduction_kw": 150.0},
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-003",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_esc_04",
        )
        action.authorization_evidence = evidence

        policy_res, prov_res, risk_res, decision = self._evaluate_pipeline(action)

        self.assertEqual(policy_res.decision, "block")
        self.assertFalse(prov_res.verified)
        self.assertEqual(prov_res.status, "parameter_exceeded")
        self.assertEqual(decision.final_decision, "block")

    # =========================================================================
    # 5. CO-APPROVAL ENFORCEMENT -> BLOCK
    # =========================================================================

    def test_missing_co_approval_receives_block(self):
        """PERS-004 attempting SHUTDOWN_LOAD alone (requires co-approval): receives BLOCK."""
        action = ProposedAction(
            action_id="act_co_01",
            run_id="run_co_01",
            session_id="sess_co_01",
            action_type="SHUTDOWN_LOAD",
            target="load_1",
            reason="Sole engineer attempting feeder shutdown",
            priority="HIGH",
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-004",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_co_01",
            co_signer_id=None,
        )
        action.authorization_evidence = evidence

        policy_res, prov_res, risk_res, decision = self._evaluate_pipeline(action)

        self.assertEqual(policy_res.decision, "block")
        self.assertFalse(prov_res.verified)
        self.assertEqual(prov_res.status, "missing_co_approval")
        self.assertEqual(decision.final_decision, "block")

    def test_invalid_co_signer_receives_block(self):
        """PERS-004 co-signed by revoked/expired PERS-005: receives BLOCK."""
        action = ProposedAction(
            action_id="act_co_02",
            run_id="run_co_02",
            session_id="sess_co_02",
            action_type="SHUTDOWN_LOAD",
            target="load_1",
            reason="Engineer co-signed with revoked credentials",
            priority="HIGH",
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-004",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_co_02",
            co_signer_id="PERS-005",
        )
        action.authorization_evidence = evidence

        policy_res, prov_res, risk_res, decision = self._evaluate_pipeline(action)

        self.assertEqual(policy_res.decision, "block")
        self.assertFalse(prov_res.verified)
        self.assertEqual(prov_res.status, "invalid_co_signer")
        self.assertEqual(decision.final_decision, "block")

    # =========================================================================
    # 6. REVOKED & EXPIRED CREDENTIALS -> BLOCK
    # =========================================================================

    def test_revoked_personnel_credential_receives_block(self):
        """PERS-005 (Deactivated / Revoked) receives BLOCK."""
        action = ProposedAction(
            action_id="act_rev_01",
            run_id="run_rev_01",
            session_id="sess_rev_01",
            action_type="INSPECT",
            target="none",
            reason="Deactivated analyst attempting inspection",
            priority="LOW",
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-005",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_rev_01",
        )
        action.authorization_evidence = evidence

        policy_res, prov_res, risk_res, decision = self._evaluate_pipeline(action)

        self.assertEqual(policy_res.decision, "block")
        self.assertFalse(prov_res.verified)
        self.assertEqual(prov_res.status, "revoked_credential")
        self.assertEqual(decision.final_decision, "block")

    def test_expired_personnel_credential_receives_block(self):
        """Active operator evaluated outside validity period receives BLOCK."""
        action = ProposedAction(
            action_id="act_exp_01",
            run_id="run_exp_01",
            session_id="sess_exp_01",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Evaluation timestamp after credential expiry",
            priority="MEDIUM",
            parameters={"reduction_kw": 50.0},
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_exp_01",
        )
        action.authorization_evidence = evidence

        # Evaluation in year 2030 (credential valid only in 2026)
        future_now = datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        policy_res = verify_policy(action, personnel_registry=self.registry, now=future_now)
        prov_res = verify_provenance(action, personnel_registry=self.registry, now=future_now)
        replay_res = ReplayCheckResult(detected=False, reason="Fresh", fingerprint="fp1", observation_timestamp="12:00")
        risk_res = evaluate_risk(policy_res, prov_res, self.benign_behaviour, replay_res)
        decision = make_decision(action, policy_res, prov_res, self.benign_behaviour, risk_res)

        self.assertEqual(policy_res.decision, "block")
        self.assertFalse(prov_res.verified)
        self.assertEqual(prov_res.status, "expired_credential")
        self.assertEqual(decision.final_decision, "block")

    # =========================================================================
    # 7. MISSING PROVENANCE & UNCOMMITTED TOKENS -> BLOCK
    # =========================================================================

    def test_claimed_pers_id_without_cryptographic_evidence_receives_block(self):
        """Action claiming 'PERS-001' string without cryptographic evidence receives BLOCK."""
        action = ProposedAction(
            action_id="act_unauth_01",
            run_id="run_unauth_01",
            session_id="sess_unauth_01",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Unauthenticated claim of PERS-001",
            priority="MEDIUM",
            claimed_authorization="PERS-001",
            parameters={"reduction_kw": 50.0},
        )
        policy_res, prov_res, risk_res, decision = self._evaluate_pipeline(action)

        self.assertEqual(policy_res.decision, "block")
        self.assertFalse(prov_res.verified)
        self.assertEqual(prov_res.status, "missing_credential")
        self.assertEqual(decision.final_decision, "block")

    def test_severe_action_with_empty_authorization_receives_block(self):
        """ISOLATE_BATTERY proposed with empty authorization receives BLOCK."""
        action = ProposedAction(
            action_id="act_empty_01",
            run_id="run_empty_01",
            session_id="sess_empty_01",
            action_type="ISOLATE_BATTERY",
            target="battery_1",
            reason="Severe action with no claimed authority",
            priority="HIGH",
        )
        policy_res, prov_res, risk_res, decision = self._evaluate_pipeline(action)

        self.assertEqual(policy_res.decision, "block")
        self.assertFalse(prov_res.verified)
        self.assertEqual(decision.final_decision, "block")

    # =========================================================================
    # 8. DIRECT CONTROLLER GATE 3 INDEPENDENT ENFORCEMENT -> BLOCK
    # =========================================================================

    def test_controller_gate3_blocks_even_if_policy_is_permissive(self):
        """
        Even if policy returns 'allow', Gate 3 in make_decision must independently
        enforce a hard BLOCK on unverified personnel authorization.
        """
        action = ProposedAction(
            action_id="act_gate3_01",
            run_id="run_gate3_01",
            session_id="sess_gate3_01",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="Test Gate 3 independent block",
            priority="LOW",
        )
        permissive_policy = PolicyResult(
            decision="allow",
            matched_rule_id="default_allow",
            reason="Permissive test rule",
        )
        failed_prov = ProvenanceResult(
            verified=False,
            trace_length=0,
            status="invalid_signature",
            reason="Cryptographic signature verification failed",
            auth_type="personnel",
            personnel_id="PERS-001",
        )
        low_risk = RiskResult(
            score=0.2,
            band="LOW",
            contributing_factors={},
            replay_detected=False,
        )

        decision = make_decision(
            action=action,
            policy_res=permissive_policy,
            prov_res=failed_prov,
            behav_res=self.benign_behaviour,
            risk_res=low_risk,
        )

        self.assertEqual(decision.final_decision, "block")
        self.assertIn("Provenance Denied", decision.reason)

    def test_controller_gate3_blocks_all_personnel_status_codes(self):
        """Verify all specific personnel status codes trigger a hard BLOCK at Gate 3."""
        status_codes = [
            "unknown_personnel",
            "missing_signature",
            "invalid_signature",
            "revoked_credential",
            "expired_credential",
            "unauthorized_action",
            "unauthorized_target",
            "priority_exceeded",
            "parameter_exceeded",
            "missing_co_approval",
            "invalid_co_signer",
            "missing_credential",
            "unverified_personnel",
        ]
        action = ProposedAction(
            action_id="act_codes_01",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="Test all status codes",
            priority="LOW",
        )
        permissive_policy = PolicyResult(decision="allow", reason="Permissive rule")
        low_risk = RiskResult(score=0.2, band="LOW", contributing_factors={}, replay_detected=False)

        for status in status_codes:
            prov = ProvenanceResult(
                verified=False,
                trace_length=0,
                status=status,
                reason=f"Failed with {status}",
                auth_type="personnel",
            )
            dec = make_decision(action, permissive_policy, prov, self.benign_behaviour, low_risk)
            self.assertEqual(dec.final_decision, "block", f"Status '{status}' did not produce BLOCK")
            self.assertIn("Provenance Denied", dec.reason)

    # =========================================================================
    # 9. PHYSICAL SAFETY RULES OVERRIDE VALID CREDENTIALS -> BLOCK
    # =========================================================================

    def test_battery_isolation_on_normal_telemetry_blocked_despite_valid_credential(self):
        """
        PERS-004 has permission for ISOLATE_BATTERY, but battery telemetry is NORMAL (30C).
        Physical safety rule_002c must BLOCK and CANNOT be overridden by valid credentials.
        """
        action = ProposedAction(
            action_id="act_phys_01",
            run_id="run_phys_01",
            session_id="sess_phys_01",
            action_type="ISOLATE_BATTERY",
            target="battery_1",
            reason="Operator attempts unnecessary battery disconnection",
            priority="HIGH",
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-004",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_phys_01",
        )
        action.authorization_evidence = evidence

        # Normal microgrid operating context
        normal_context = {
            "battery_temperature_c": 30.0,
            "report_status": "NORMAL",
            "voltage_pu": 1.0,
        }

        policy_res, prov_res, risk_res, decision = self._evaluate_pipeline(
            action, context=normal_context
        )

        self.assertEqual(policy_res.decision, "block")
        self.assertEqual(policy_res.matched_rule_id, "rule_002c")
        self.assertTrue(prov_res.verified)  # Credentials were cryptographically valid
        self.assertEqual(decision.final_decision, "block")
        self.assertIn("Policy Override", decision.reason)

    def test_physical_safety_load_reduction_limits_blocked_despite_valid_credential(self):
        """
        PERS-004 proposes physically impossible negative load reduction.
        Physical constraint rule_006 and parameter limits must BLOCK despite valid credentials.
        """
        action = ProposedAction(
            action_id="act_phys_02",
            run_id="run_phys_02",
            session_id="sess_phys_02",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Operator proposes negative reduction setpoint",
            priority="MEDIUM",
            parameters={"reduction_kw": -10.0},
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-004",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_phys_02",
        )
        action.authorization_evidence = evidence

        policy_res, prov_res, risk_res, decision = self._evaluate_pipeline(action)

        self.assertEqual(policy_res.decision, "block")
        self.assertEqual(decision.final_decision, "block")

    # =========================================================================
    # 10. TELEMETRY REPLAY REJECTION OVERRIDES VALID CREDENTIALS -> BLOCK
    # =========================================================================

    def test_replay_attack_overrides_valid_credential(self):
        """
        Observation telemetry is flagged as a replay attack.
        Controller must return BLOCK even when action has valid, in-scope personnel credential.
        """
        action = ProposedAction(
            action_id="act_replay_01",
            run_id="run_replay_01",
            session_id="sess_replay_01",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="Legitimate operator action during replayed telemetry",
            priority="LOW",
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_replay_01",
        )
        action.authorization_evidence = evidence

        policy_res, prov_res, risk_res, decision = self._evaluate_pipeline(
            action, replay_detected=True
        )

        self.assertEqual(policy_res.decision, "allow")
        self.assertTrue(prov_res.verified)
        self.assertTrue(risk_res.replay_detected)
        self.assertEqual(decision.final_decision, "block")
        self.assertIn("replay attack", decision.reason.lower())

    # =========================================================================
    # 11. MANDATORY HUMAN_APPROVAL CANNOT BE OVERRIDDEN BY VALID CREDENTIALS
    # =========================================================================

    def test_critical_load_shutdown_requires_human_approval_despite_valid_co_approval(self):
        """
        PERS-004 and PERS-001 submit fully co-approved authorization for SHUTDOWN_LOAD on critical_load.
        Policy rule_001 mandates HUMAN_APPROVAL. Valid credentials CANNOT override this to ALLOW.
        """
        # Ensure co-signer PERS-001 has target permission for critical_load in this test
        self.registry.get_personnel("PERS-001").permitted_targets.add("critical_load")

        action = ProposedAction(
            action_id="act_crit_01",
            run_id="run_crit_01",
            session_id="sess_crit_01",
            action_type="SHUTDOWN_LOAD",
            target="critical_load",
            reason="Planned critical infrastructure load shedding",
            priority="HIGH",
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-004",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_crit_01",
            co_signer_id="PERS-001",  # PERS-001 has SHUTDOWN_LOAD permission
        )
        action.authorization_evidence = evidence

        policy_res, prov_res, risk_res, decision = self._evaluate_pipeline(action)

        self.assertEqual(policy_res.decision, "human_approval")
        self.assertEqual(policy_res.matched_rule_id, "rule_001")
        self.assertTrue(prov_res.verified)
        self.assertEqual(decision.final_decision, "human_approval")
        self.assertIn("human approval", decision.reason.lower())

    # =========================================================================
    # 12. DIAGNOSTIC REPORT PROVENANCE PRESERVATION
    # =========================================================================

    def test_diagnostic_report_provenance_preserved(self):
        """Automated diagnostic report action with valid report lineage receives ALLOW."""
        action = ProposedAction(
            action_id="act_diag_01",
            run_id="run_diag_01",
            session_id="sess_diag_01",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="Automated monitoring maintenance",
            priority="LOW",
            claimed_authorization="rep_diag_20260615_01",
        )
        mock_neo = Mock()
        mock_neo.driver = Mock()
        mock_neo.authorization_status.return_value = "verified"

        with (
            patch("aegis.provenance.get_neo4j_client", return_value=mock_neo),
            patch("database.sqlite.is_report_consumed", return_value=False),
        ):
            policy_res, prov_res, risk_res, decision = self._evaluate_pipeline(action)

        self.assertEqual(policy_res.decision, "allow")
        self.assertTrue(prov_res.verified)
        self.assertEqual(prov_res.auth_type, "diagnostic_report")
        self.assertEqual(decision.final_decision, "allow")

    def test_reused_diagnostic_report_receives_block(self):
        """Automated diagnostic report reuse is detected and receives BLOCK."""
        action = ProposedAction(
            action_id="act_diag_02",
            run_id="run_diag_02",
            session_id="sess_diag_02",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="Automated action reusing claimed report",
            priority="LOW",
            claimed_authorization="rep_already_consumed_01",
        )
        with patch("database.sqlite.is_report_consumed", return_value=True):
            policy_res, prov_res, risk_res, decision = self._evaluate_pipeline(action)

        self.assertFalse(prov_res.verified)
        self.assertEqual(prov_res.status, "report_reused")
        self.assertEqual(decision.final_decision, "block")

    # =========================================================================
    # 12b. PERSONNEL AUTHORIZATION REPLAY REPRODUCTION (VULNERABILITY CONFIRMATION)
    # =========================================================================

    def test_reproduce_personnel_credential_replay_vulnerability_same_session(self):
        """
        DEFENSE VERIFICATION: Confirms personnel AuthorizationEvidence cannot be replayed
        within the same session. Reused nonces receive hard BLOCK.
        """
        # Step 1: Issue valid personnel authorization for 50 kW load reduction
        act_orig = ProposedAction(
            action_id="act_legit_load_01",
            run_id="run_sess_01_a",
            session_id="session_replay_01",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Legitimate peak reduction authorized by Lead Dispatcher",
            priority="MEDIUM",
            parameters={"reduction_kw": 50.0},
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=act_orig,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_replay_test_01",
        )
        act_orig.authorization_evidence = evidence

        # Original action is evaluated and allowed
        pol_orig, prov_orig, risk_orig, dec_orig = self._evaluate_pipeline(act_orig)
        self.assertEqual(dec_orig.final_decision, "allow")
        self.assertTrue(prov_orig.verified)

        # Step 2: Adversary replays identical AuthorizationEvidence on duplicate action in SAME session
        act_duplicate = act_orig.model_copy(deep=True)
        pol_dup, prov_dup, risk_dup, dec_dup = self._evaluate_pipeline(act_duplicate)

        # Single-use enforcement: Replay receives hard BLOCK with credential_reused
        self.assertEqual(dec_dup.final_decision, "block")
        self.assertFalse(prov_dup.verified)
        self.assertEqual(prov_dup.status, "credential_reused")

        # Step 3: Adversary modifies action_id to attempt bypassing action-level tracking
        act_replayed = ProposedAction(
            action_id="act_replayed_load_02",
            run_id="run_sess_01_b",
            session_id="session_replay_01",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Adversary replays captured authorization evidence to shed more load",
            priority="MEDIUM",
            parameters={"reduction_kw": 50.0},
        )
        act_replayed.authorization_evidence = evidence

        pol_rep, prov_rep, risk_rep, dec_rep = self._evaluate_pipeline(act_replayed)
        self.assertEqual(dec_rep.final_decision, "block")
        self.assertFalse(prov_rep.verified)
        self.assertIn(prov_rep.status, ["credential_reused", "action_digest_mismatch", "invalid_signature", "tampered_action"])

    def test_reproduce_personnel_credential_replay_vulnerability_cross_session(self):
        """
        DEFENSE VERIFICATION: Confirms personnel AuthorizationEvidence cannot be replayed
        across DIFFERENT sessions. Global single-use enforcement ensures hard BLOCK.
        """
        act_orig = ProposedAction(
            action_id="act_sess1_01",
            run_id="run_sess1",
            session_id="session_01",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Session 1 authorized dispatch",
            priority="MEDIUM",
            parameters={"reduction_kw": 50.0},
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=act_orig,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_cross_session_01",
        )
        act_orig.authorization_evidence = evidence

        # Session 1 allows original action
        _, prov_orig, _, dec_orig = self._evaluate_pipeline(act_orig)
        self.assertEqual(dec_orig.final_decision, "allow")

        # Session 2: Adversary submits action in session_02 replaying Session 1 evidence
        act_cross_session = ProposedAction(
            action_id="act_sess2_replay",
            run_id="run_sess2",
            session_id="session_02",  # Different session!
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Cross-session replay of captured credentials",
            priority="MEDIUM",
            parameters={"reduction_kw": 50.0},
        )
        act_cross_session.authorization_evidence = evidence

        pol_cross, prov_cross, risk_cross, dec_cross = self._evaluate_pipeline(act_cross_session)

        # Cross-session replay is rejected with hard BLOCK
        self.assertEqual(dec_cross.final_decision, "block")
        self.assertFalse(prov_cross.verified)
        self.assertIn(prov_cross.status, ["credential_reused", "action_digest_mismatch", "invalid_signature", "tampered_action"])

    def test_reproduce_personnel_credential_replay_via_attack_module(self):
        """
        DEFENSE VERIFICATION: Uses attacks/authority_spoofing.py personnel_replay variant
        to confirm attack module replay attempt is now blocked.
        """
        from attacks.authority_spoofing import apply_personnel_credential_replay

        # Step 1: Legitimate dispatch allowed
        legit_act = ProposedAction(
            action_id="act_legit_01",
            run_id="run_orig",
            session_id="session_orig",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Scheduled peak shaving",
            priority="MEDIUM",
            parameters={"reduction_kw": 50.0},
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=legit_act,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_attack_replay",
        )
        legit_act.authorization_evidence = evidence
        _, _, _, dec_orig = self._evaluate_pipeline(legit_act)
        self.assertEqual(dec_orig.final_decision, "allow")

        # Step 2: Adversary applies attack module to replay intercepted evidence
        replayed_action_template = ProposedAction(
            action_id="act_attack_replay",
            run_id="run_attack",
            session_id="session_attack",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Unauthorized secondary reduction using intercepted credentials",
            priority="MEDIUM",
            parameters={"reduction_kw": 50.0},
        )
        replayed_act = apply_personnel_credential_replay(
            action=replayed_action_template,
            intercepted_evidence=evidence,
        )

        # Step 3: Evaluate against AEGIS pipeline
        pol_rep, prov_rep, risk_rep, dec_rep = self._evaluate_pipeline(replayed_act)

        # Replay attempt receives hard BLOCK
        self.assertEqual(dec_rep.final_decision, "block")
        self.assertFalse(prov_rep.verified)

    def test_concurrent_duplicate_personnel_credentials_cannot_both_succeed(self):
        """Concurrent submissions attempting to consume the same credential cannot both succeed."""
        import json
        import concurrent.futures
        from database.sqlite import persist_decision_and_consume_report

        action = ProposedAction(
            action_id="act_conc_01",
            run_id="run_conc",
            session_id="sess_conc",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Concurrent test load reduction",
            priority="MEDIUM",
            parameters={"reduction_kw": 50.0},
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_concurrent_01",
        )

        from database.models import AEGISDecisionRow

        def attempt_persist(thread_idx):
            decision_row = AEGISDecisionRow(
                run_id="run_conc",
                session_id="sess_conc",
                timestamp=self.fixed_now.isoformat(),
                action_id=action.action_id,
                policy_result="{}",
                provenance_result="{}",
                behaviour_flag=0,
                risk_score=0.1,
                final_decision="allow",
                reason=f"Concurrent test {thread_idx}",
            )
            outbox_payload = {"event": "DECISION_CREATED", "decision_id": f"dec_conc_{thread_idx}"}
            success, _ = persist_decision_and_consume_report(
                decision_row=decision_row,
                report_id=None,
                action_digest="digest_test",
                outbox_payload=outbox_payload,
                personnel_evidence=evidence,
                db_path=self.db_path,
            )
            return success

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(attempt_persist, i) for i in range(8)]
            results = [f.result() for f in futures]

        # Exactly 1 submission succeeds, the other 7 fail due to atomicity & unique constraint
        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 7)

    def test_tampered_action_id_fails_cryptographic_context_binding(self):
        """Action signed for action_id='act_bound_01' fails verification when bound action_id is altered."""
        action = ProposedAction(
            action_id="act_bound_01",
            run_id="run_bound_01",
            session_id="sess_bound_01",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Original dispatch",
            priority="LOW",
            parameters={"reduction_kw": 50.0},
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_bound_01",
        )
        action.authorization_evidence = evidence

        # Adversary alters action_id in-flight
        action.action_id = "act_bound_tampered"

        policy_res, prov_res, risk_res, decision = self._evaluate_pipeline(action)

        self.assertFalse(prov_res.verified)
        self.assertEqual(decision.final_decision, "block")
        self.assertIn(prov_res.status, ["tampered_action", "invalid_signature", "action_digest_mismatch"])

    def test_co_approval_evidence_cannot_be_replayed(self):
        """Both primary and co-signer nonces are consumed; neither can be replayed together or independently."""
        action = ProposedAction(
            action_id="act_co_01",
            run_id="run_co_01",
            session_id="sess_co_01",
            action_type="SHUTDOWN_LOAD",
            target="load_1",
            reason="Planned maintenance load shutdown requiring co-approval",
            priority="HIGH",
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-004",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_co_dual_01",
            co_signer_id="PERS-001",
        )
        action.authorization_evidence = evidence

        # First use: valid dual authorization succeeds
        pol_1, prov_1, risk_1, dec_1 = self._evaluate_pipeline(action)
        self.assertEqual(dec_1.final_decision, "allow")
        self.assertTrue(prov_1.verified)

        # Both primary and co-signer nonces are now consumed
        self.assertTrue(is_personnel_credential_consumed("PERS-004", "nonce_co_dual_01", db_path=self.db_path))
        self.assertTrue(is_personnel_credential_consumed("PERS-001", "nonce_co_dual_01", db_path=self.db_path))

        # Replay attempt 1: Replay exact co-approved action
        act_replay_all = action.model_copy(deep=True)
        _, prov_rep1, _, dec_rep1 = self._evaluate_pipeline(act_replay_all)
        self.assertEqual(dec_rep1.final_decision, "block")
        self.assertFalse(prov_rep1.verified)
        self.assertEqual(prov_rep1.status, "credential_reused")

        # Replay attempt 2: Adversary tries to reuse co-signer's consumed nonce with a different primary request
        act_steal_co = ProposedAction(
            action_id="act_co_steal",
            run_id="run_co_steal",
            session_id="sess_co_steal",
            action_type="SHUTDOWN_LOAD",
            target="load_1",
            reason="Attempting to piggyback on consumed co-signer nonce",
            priority="HIGH",
        )
        stolen_evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-004",
            action=act_steal_co,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_new_primary_02",
            co_signer_id="PERS-001",
        )
        # Point co-signer signature to the already-consumed nonce
        stolen_evidence.nonce = "nonce_co_dual_01"
        act_steal_co.authorization_evidence = stolen_evidence

        _, prov_rep2, _, dec_rep2 = self._evaluate_pipeline(act_steal_co)
        self.assertEqual(dec_rep2.final_decision, "block")
        self.assertFalse(prov_rep2.verified)

    def test_blocked_action_not_recorded_in_behaviour_history(self):
        """Failed or blocked actions are pruned so they never contaminate trusted behavioural history."""
        action = ProposedAction(
            action_id="act_blocked_beh",
            run_id="run_blocked_beh",
            session_id="sess_blocked_beh",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Forged dispatch to test behaviour isolation",
            priority="MEDIUM",
            parameters={"reduction_kw": 50.0},
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_blocked_beh",
        )
        evidence.signature = "invalid_sig"
        action.authorization_evidence = evidence

        neo_mock = Mock()
        neo_mock.log_aegis_decision.return_value = True

        state = {
            "observation": {"timestamp": "12:00", "battery_temperature_c": 30.0, "voltage_pu": 1.0},
            "run_id": "run_blocked_beh",
            "session_id": "sess_blocked_beh",
            "proposed_action": action,
            "attack_context": graph.AttackContext(is_injected_attack=False, attack_type=None),
            "personnel_registry": self.registry,
            "now": self.fixed_now,
        }

        with (
            patch("workflow.graph.persist_decision_and_consume_report", return_value=(True, 1)),
            patch("workflow.graph.get_neo4j_client", return_value=neo_mock),
            patch("workflow.graph.sync_neo4j_outbox", return_value=1),
        ):
            pol_state = graph.aegis_policy_node(state)
            state.update(pol_state)
            prov_state = graph.aegis_provenance_node(state)
            state.update(prov_state)
            beh_state = graph.aegis_behaviour_node(state)
            state.update(beh_state)
            risk_state = graph.aegis_risk_node(state)
            state.update(risk_state)
            dec_state = graph.decision_controller_node(state)

        res = dec_state["workflow_result"]
        self.assertEqual(res.final_decision, "block")

        # Verify action was not kept in trusted behaviour baseline
        recent_actions = get_recent_history(agent=action.sender_agent or "response_agent")
        action_ids = [a.action_id for a in recent_actions]
        self.assertNotIn("act_blocked_beh", action_ids)

    # =========================================================================
    # 13. END-TO-END WORKFLOW INTEGRATION
    # =========================================================================

    def test_workflow_end_to_end_authorized_personnel_action_allows_and_avoids_report_consumption(self):
        """
        End-to-end workflow execution with a valid personnel credential:
        - Result is ALLOW
        - personnel_evidence is passed to persist_decision_and_consume_report
        - report_id_to_consume is None so SQLite consumed_reports is not polluted.
        """
        action = ProposedAction(
            action_id="act_wf_01",
            run_id="run_wf_01",
            session_id="sess_wf_01",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Operator load shed",
            priority="MEDIUM",
            parameters={"reduction_kw": 50.0},
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_wf_01",
        )
        action.authorization_evidence = evidence

        persisted_reports = []

        def mock_persist(decision_row, report_id, action_digest, outbox_payload, personnel_evidence=None, **kwargs):
            persisted_reports.append((report_id, personnel_evidence))
            return True, 1

        neo_mock = Mock()
        neo_mock.log_aegis_decision.return_value = True

        state = {
            "observation": {"timestamp": "12:00", "battery_temperature_c": 30.0, "voltage_pu": 1.0},
            "run_id": "run_wf_01",
            "session_id": "sess_wf_01",
            "proposed_action": action,
            "attack_context": graph.AttackContext(is_injected_attack=False, attack_type=None),
            "personnel_registry": self.registry,
            "now": self.fixed_now,
        }

        with (
            patch("workflow.graph.persist_decision_and_consume_report", side_effect=mock_persist),
            patch("workflow.graph.get_neo4j_client", return_value=neo_mock),
            patch("workflow.graph.sync_neo4j_outbox", return_value=1),
        ):
            pol_state = graph.aegis_policy_node(state)
            state.update(pol_state)
            prov_state = graph.aegis_provenance_node(state)
            state.update(prov_state)
            beh_state = graph.aegis_behaviour_node(state)
            state.update(beh_state)
            risk_state = graph.aegis_risk_node(state)
            state.update(risk_state)
            dec_state = graph.decision_controller_node(state)

        res = dec_state["workflow_result"]
        self.assertEqual(res.final_decision, "allow")
        self.assertEqual(persisted_reports, [(None, evidence)])

    def test_workflow_end_to_end_forged_personnel_action_blocks(self):
        """End-to-end workflow execution with forged personnel credential returns BLOCK."""
        action = ProposedAction(
            action_id="act_wf_forge",
            run_id="run_wf_forge",
            session_id="sess_wf_forge",
            action_type="REDUCE_LOAD",
            target="load_1",
            reason="Attacker forged dispatch",
            priority="MEDIUM",
            parameters={"reduction_kw": 50.0},
        )
        evidence = self.signing_auth.issue_evidence(
            personnel_id="PERS-001",
            action=action,
            issued_at=self.fixed_now.isoformat(),
            nonce="nonce_wf_forge",
        )
        evidence.signature = "bad_signature"
        action.authorization_evidence = evidence

        neo_mock = Mock()
        neo_mock.log_aegis_decision.return_value = True

        state = {
            "observation": {"timestamp": "12:00", "battery_temperature_c": 30.0, "voltage_pu": 1.0},
            "run_id": "run_wf_forge",
            "session_id": "sess_wf_forge",
            "proposed_action": action,
            "attack_context": graph.AttackContext(is_injected_attack=False, attack_type=None),
            "personnel_registry": self.registry,
            "now": self.fixed_now,
        }

        with (
            patch("workflow.graph.persist_decision_and_consume_report", return_value=(True, 1)),
            patch("workflow.graph.get_neo4j_client", return_value=neo_mock),
            patch("workflow.graph.sync_neo4j_outbox", return_value=1),
        ):
            pol_state = graph.aegis_policy_node(state)
            state.update(pol_state)
            prov_state = graph.aegis_provenance_node(state)
            state.update(prov_state)
            beh_state = graph.aegis_behaviour_node(state)
            state.update(beh_state)
            risk_state = graph.aegis_risk_node(state)
            state.update(risk_state)
            dec_state = graph.decision_controller_node(state)

        res = dec_state["workflow_result"]
        self.assertEqual(res.final_decision, "block")
        self.assertTrue(
            "Policy Override" in res.aegis_result.reason or "Provenance Denied" in res.aegis_result.reason
        )


if __name__ == "__main__":
    unittest.main()
