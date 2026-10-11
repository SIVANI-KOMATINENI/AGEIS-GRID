"""
behaviour_test.py
Focused test suite for AEGIS GRID Behaviour Analysis Layer.

Verifies:
1. History isolation across agents and test resets.
2. Insufficient baseline / cold-start safety (routine vs severe actions).
3. Suspicious action sequences (steady-state to abrupt disconnect, priority flip-flop, rapid target divergence).
4. Action frequency and repetition anomalies (high priority burst, repeated disruptive, back-to-back disruptive, target concentration).
5. Baseline poisoning prevention (quarantine isolation, repeated attack mitigation, explicit discard/quarantine).
6. Deterministic primacy over LLM guidance (LLM cannot downgrade, LLM can elevate, malformed input resilience).
7. Database history loading with runtime security outcome filtering (no ground-truth labels).
8. Legitimate normal operational workflows (clean zero scores, no false positive blocking).
"""

import os
import tempfile
import unittest
import sqlite3
from typing import Dict, Any

from agents.schemas import ProposedAction
import config as cfg
from database.models import AgentMessageRow, AEGISDecisionRow
from database.sqlite import init_db, insert_agent_message, persist_decision_and_consume_report
from aegis.behaviour import (
    analyze_behaviour,
    reset_behaviour_history,
    record_trusted_action,
    discard_untrusted_action,
    quarantine_action,
    get_recent_history,
    get_quarantined_history,
    load_behaviour_history_from_db,
    set_db_load_enabled,
    BehaviourResult,
    MIN_BASELINE_DEPTH,
    SCORE_INSUFFICIENT_BASELINE_SEVERE,
    SCORE_SPARSE_BASELINE_SEVERE,
    SCORE_UNSEEN_ACTION,
    SCORE_PRIORITY_ESCALATION,
    SCORE_HIGH_PRIORITY_BURST,
    SCORE_REPEATED_DISRUPTIVE,
    SCORE_CONSECUTIVE_DISRUPTIVE,
    SCORE_TARGET_CONCENTRATION,
    SCORE_RAPID_TARGET_PIVOT,
    SCORE_UNUSUAL_SEQUENCE,
    SCORE_PRIORITY_FLIP_FLOP,
    ANOMALY_QUARANTINE_THRESHOLD,
)


class TestBehaviourHistoryIsolation(unittest.TestCase):
    """Test history isolation across agents and resets."""

    def setUp(self):
        reset_behaviour_history(enable_db_load=False)

    def tearDown(self):
        reset_behaviour_history(enable_db_load=False)

    def test_history_isolation_across_agents(self):
        """Actions for response_agent must not affect history of backup_agent."""
        act_resp = ProposedAction(
            action_id="act_resp_1",
            sender_agent="response_agent",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="routine",
            priority="LOW",
        )
        analyze_behaviour(act_resp)

        resp_hist = get_recent_history("response_agent")
        backup_hist = get_recent_history("backup_agent")

        self.assertEqual(len(resp_hist), 1)
        self.assertEqual(len(backup_hist), 0)

    def test_reset_behaviour_history_clears_memory_and_quarantine(self):
        """reset_behaviour_history clears both trusted and quarantined histories."""
        routine = ProposedAction(
            action_id="act_rout_1",
            sender_agent="response_agent",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="routine",
            priority="LOW",
        )
        severe = ProposedAction(
            action_id="act_sev_1",
            sender_agent="response_agent",
            action_type="ISOLATE_BATTERY",
            target="battery_1",
            reason="fire",
            priority="HIGH",
        )
        analyze_behaviour(routine)
        analyze_behaviour(severe)

        self.assertGreater(len(get_recent_history("response_agent")), 0)
        self.assertGreater(len(get_quarantined_history("response_agent")), 0)

        reset_behaviour_history(enable_db_load=False)

        self.assertEqual(len(get_recent_history("response_agent")), 0)
        self.assertEqual(len(get_quarantined_history("response_agent")), 0)


class TestInsufficientBaselineHandling(unittest.TestCase):
    """Test cold-start and sparse baseline behaviour."""

    def setUp(self):
        reset_behaviour_history(enable_db_load=False)

    def tearDown(self):
        reset_behaviour_history(enable_db_load=False)

    def test_empty_baseline_routine_action_passes(self):
        """Routine action on empty history passes as baseline bootstrap."""
        action = ProposedAction(
            action_id="act_boot_1",
            sender_agent="response_agent",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="Normal startup bootstrap.",
            priority="LOW",
        )
        res = analyze_behaviour(action)
        self.assertFalse(res.flagged)
        self.assertEqual(res.score, 0.0)
        self.assertFalse(res.quarantined)
        self.assertEqual(res.history_length, 0)
        self.assertIn("No baseline history yet", res.deviation_reason or "")

    def test_empty_baseline_severe_action_flagged_and_quarantined(self):
        """High-impact action on empty history must NOT be assumed safe."""
        action = ProposedAction(
            action_id="act_attack_cold",
            sender_agent="response_agent",
            action_type="ISOLATE_BATTERY",
            target="battery_1",
            reason="Unsubstantiated emergency",
            priority="HIGH",
        )
        res = analyze_behaviour(action)
        self.assertTrue(res.flagged)
        self.assertEqual(res.score, SCORE_INSUFFICIENT_BASELINE_SEVERE)
        self.assertTrue(res.quarantined)
        self.assertIn("insufficient_baseline_severe", res.anomaly_types)
        self.assertIn("Insufficient baseline history", res.deviation_reason or "")
        # Must be in quarantine, NOT in trusted history
        self.assertEqual(len(get_recent_history("response_agent")), 0)
        self.assertEqual(len(get_quarantined_history("response_agent")), 1)

    def test_empty_baseline_shutdown_load_flagged(self):
        """SHUTDOWN_LOAD on empty history is flagged for insufficient baseline."""
        action = ProposedAction(
            action_id="act_shutdown_cold",
            sender_agent="response_agent",
            action_type="SHUTDOWN_LOAD",
            target="load_1",
            reason="Abrupt shutdown",
            priority="LOW",
        )
        res = analyze_behaviour(action)
        self.assertTrue(res.flagged)
        self.assertEqual(res.score, SCORE_INSUFFICIENT_BASELINE_SEVERE)
        self.assertTrue(res.quarantined)

    def test_sparse_baseline_penalty_on_severe_actions(self):
        """When baseline depth < MIN_BASELINE_DEPTH, severe actions receive sparse penalty."""
        # Add 1 routine action to establish sparse baseline of depth 1
        act1 = ProposedAction(
            action_id="act_b1",
            sender_agent="response_agent",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="init",
            priority="LOW",
        )
        analyze_behaviour(act1)
        self.assertEqual(len(get_recent_history("response_agent")), 1)

        # Propose severe action before MIN_BASELINE_DEPTH (3) is reached
        severe_act = ProposedAction(
            action_id="act_b2_severe",
            sender_agent="response_agent",
            action_type="ISOLATE_BATTERY",
            target="battery_1",
            reason="Abrupt severe",
            priority="HIGH",
        )
        res = analyze_behaviour(severe_act)
        self.assertTrue(res.flagged)
        self.assertIn("sparse_baseline_severe", res.anomaly_types)
        self.assertIn("unseen_action_type", res.anomaly_types)
        # Score includes sparse baseline + unseen + priority escalation
        expected_min = SCORE_SPARSE_BASELINE_SEVERE + SCORE_UNSEEN_ACTION
        self.assertGreaterEqual(res.score, expected_min)


class TestSuspiciousActionSequences(unittest.TestCase):
    """Test detection of abnormal sequence transitions and oscillations."""

    def setUp(self):
        reset_behaviour_history(enable_db_load=False)
        # Prepopulate with 3 steady-state actions to establish normal baseline
        for i in range(3):
            record_trusted_action(
                ProposedAction(
                    action_id=f"act_steady_{i}",
                    sender_agent="response_agent",
                    action_type="MAINTAIN_STATUS",
                    target="none",
                    reason="normal steady state",
                    priority="LOW",
                )
            )

    def tearDown(self):
        reset_behaviour_history(enable_db_load=False)

    def test_unusual_sequence_abrupt_disconnect(self):
        """Abrupt jump from steady state directly to emergency disconnection is flagged."""
        abrupt_act = ProposedAction(
            action_id="act_abrupt_1",
            sender_agent="response_agent",
            action_type="ISOLATE_BATTERY",
            target="battery_1",
            reason="Immediate disconnect without prior inspection",
            priority="HIGH",
        )
        res = analyze_behaviour(abrupt_act)
        self.assertTrue(res.flagged)
        self.assertIn("unusual_sequence_abrupt_disconnect", res.anomaly_types)
        self.assertIn("Unusual sequence", res.deviation_reason or "")

    def test_priority_flip_flop_detection(self):
        """Oscillating between LOW and HIGH priority is detected as flip-flop."""
        # Establish sequence: LOW -> HIGH
        record_trusted_action(
            ProposedAction(
                action_id="act_pri_high",
                sender_agent="response_agent",
                action_type="MAINTAIN_STATUS",
                target="none",
                reason="sudden high",
                priority="HIGH",
            )
        )
        # Propose action returning to LOW (LOW -> HIGH -> LOW)
        flip_act = ProposedAction(
            action_id="act_pri_flip",
            sender_agent="response_agent",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="flip back to low",
            priority="LOW",
        )
        res = analyze_behaviour(flip_act)
        self.assertTrue(res.flagged)
        self.assertIn("priority_flip_flop", res.anomaly_types)
        self.assertIn("Flip-flop behaviour detected", res.deviation_reason or "")

    def test_rapid_target_divergence(self):
        """Hopping across 3 distinct targets in 3 consecutive actions is flagged."""
        targets = ["load_1", "battery_1"]
        for idx, t in enumerate(targets):
            record_trusted_action(
                ProposedAction(
                    action_id=f"act_tgt_{idx}",
                    sender_agent="response_agent",
                    action_type="INSPECT",
                    target=t,
                    reason="inspecting",
                    priority="LOW",
                )
            )
        # Propose 3rd action targeting yet another component (critical_load)
        pivot_act = ProposedAction(
            action_id="act_tgt_pivot",
            sender_agent="response_agent",
            action_type="INSPECT",
            target="critical_load",
            reason="rapid pivot",
            priority="LOW",
        )
        res = analyze_behaviour(pivot_act)
        self.assertTrue(res.flagged)
        self.assertIn("rapid_target_divergence", res.anomaly_types)
        self.assertIn("Rapid target divergence", res.deviation_reason or "")


class TestActionFrequencyAndRepetition(unittest.TestCase):
    """Test frequency bursts, repeated disruptive actions, and concentration."""

    def setUp(self):
        reset_behaviour_history(enable_db_load=False)
        for i in range(3):
            record_trusted_action(
                ProposedAction(
                    action_id=f"act_base_{i}",
                    sender_agent="response_agent",
                    action_type="MAINTAIN_STATUS",
                    target="none",
                    reason="baseline",
                    priority="LOW",
                )
            )

    def tearDown(self):
        reset_behaviour_history(enable_db_load=False)

    def test_high_priority_burst(self):
        """Multiple HIGH priority actions in sliding window trigger frequency anomaly."""
        for i in range(2):
            record_trusted_action(
                ProposedAction(
                    action_id=f"act_high_{i}",
                    sender_agent="response_agent",
                    action_type="INSPECT",
                    target="battery_1",
                    reason="emergency",
                    priority="HIGH",
                )
            )
        burst_act = ProposedAction(
            action_id="act_burst",
            sender_agent="response_agent",
            action_type="INSPECT",
            target="battery_1",
            reason="another high emergency",
            priority="HIGH",
        )
        res = analyze_behaviour(burst_act)
        self.assertTrue(res.flagged)
        self.assertIn("high_priority_burst", res.anomaly_types)
        self.assertIn("Frequency anomaly", res.deviation_reason or "")

    def test_repeated_disruptive_actions(self):
        """Proposing repeated disruptive actions in window triggers repeated_disruptive_actions."""
        record_trusted_action(
            ProposedAction(
                action_id="act_disr_1",
                sender_agent="response_agent",
                action_type="ISOLATE_BATTERY",
                target="battery_1",
                reason="prior disconnect",
                priority="MEDIUM",
            )
        )
        # Second disruptive action
        second_disr = ProposedAction(
            action_id="act_disr_2",
            sender_agent="response_agent",
            action_type="SHUTDOWN_LOAD",
            target="load_1",
            reason="second disconnect",
            priority="MEDIUM",
        )
        res = analyze_behaviour(second_disr)
        self.assertTrue(res.flagged)
        self.assertIn("repeated_disruptive_actions", res.anomaly_types)
        self.assertIn("Repeated disruptive actions", res.deviation_reason or "")

    def test_consecutive_back_to_back_disruptive_actions(self):
        """Immediately repeating the exact same disruptive action back-to-back is flagged."""
        record_trusted_action(
            ProposedAction(
                action_id="act_disr_init",
                sender_agent="response_agent",
                action_type="ISOLATE_BATTERY",
                target="battery_1",
                reason="first isolate",
                priority="MEDIUM",
            )
        )
        repeat_act = ProposedAction(
            action_id="act_disr_repeat",
            sender_agent="response_agent",
            action_type="ISOLATE_BATTERY",
            target="battery_1",
            reason="immediate repeat isolate",
            priority="MEDIUM",
        )
        res = analyze_behaviour(repeat_act)
        self.assertTrue(res.flagged)
        self.assertIn("consecutive_disruptive_action", res.anomaly_types)
        self.assertIn("repeated_disruptive_actions", res.anomaly_types)

    def test_target_concentration_spam(self):
        """Targeting a component repeatedly (>=3 prior times) triggers concentration penalty."""
        for i in range(3):
            record_trusted_action(
                ProposedAction(
                    action_id=f"act_conc_{i}",
                    sender_agent="response_agent",
                    action_type="INSPECT",
                    target="critical_load",
                    reason="inspect",
                    priority="LOW",
                )
            )
        concentrated_act = ProposedAction(
            action_id="act_conc_4",
            sender_agent="response_agent",
            action_type="INSPECT",
            target="critical_load",
            reason="4th inspection",
            priority="LOW",
        )
        res = analyze_behaviour(concentrated_act)
        self.assertTrue(res.flagged)
        self.assertIn("target_concentration", res.anomaly_types)
        self.assertIn("Target concentration", res.deviation_reason or "")


class TestBaselinePoisoningPrevention(unittest.TestCase):
    """Verify that anomalous and untrusted actions cannot poison baseline history."""

    def setUp(self):
        reset_behaviour_history(enable_db_load=False)
        for i in range(3):
            record_trusted_action(
                ProposedAction(
                    action_id=f"act_legit_{i}",
                    sender_agent="response_agent",
                    action_type="MAINTAIN_STATUS",
                    target="none",
                    reason="normal operation",
                    priority="LOW",
                )
            )

    def tearDown(self):
        reset_behaviour_history(enable_db_load=False)

    def test_anomalous_action_quarantined_and_not_in_trusted_history(self):
        """Actions scoring >= ANOMALY_QUARANTINE_THRESHOLD are quarantined."""
        attack_act = ProposedAction(
            action_id="act_attack_iso",
            sender_agent="response_agent",
            action_type="ISOLATE_BATTERY",
            target="battery_1",
            reason="Unauthorized isolation attempt",
            priority="HIGH",
        )
        res = analyze_behaviour(attack_act)
        self.assertTrue(res.flagged)
        self.assertTrue(res.quarantined)

        trusted = get_recent_history("response_agent")
        quarantined = get_quarantined_history("response_agent")

        self.assertNotIn("act_attack_iso", [a.action_id for a in trusted])
        self.assertIn("act_attack_iso", [a.action_id for a in quarantined])

    def test_repeated_attacks_cannot_shift_baseline(self):
        """Repeated attack attempts cannot poison baseline to make subsequent attempts pass."""
        for idx in range(3):
            attack_act = ProposedAction(
                action_id=f"act_repeat_attack_{idx}",
                sender_agent="response_agent",
                action_type="ISOLATE_BATTERY",
                target="battery_1",
                reason="Repetitive attack attempt",
                priority="HIGH",
            )
            res = analyze_behaviour(attack_act)
            # Every attempt must remain flagged and quarantined
            self.assertTrue(res.flagged, f"Attempt {idx} was not flagged")
            self.assertTrue(res.quarantined, f"Attempt {idx} was not quarantined")
            self.assertIn("unseen_action_type", res.anomaly_types, f"Attempt {idx} poisoned action types")

        # Trusted history must still only contain the original 3 legitimate actions
        trusted = get_recent_history("response_agent")
        self.assertEqual(len(trusted), 3)
        self.assertTrue(all(a.action_type == "MAINTAIN_STATUS" for a in trusted))

    def test_discard_untrusted_action_removes_from_baseline(self):
        """Downstream rejection can purge a tentatively recorded action from baseline."""
        routine_act = ProposedAction(
            action_id="act_forged_routine",
            sender_agent="response_agent",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="looks benign but has forged credential",
            priority="LOW",
        )
        res = analyze_behaviour(routine_act)
        self.assertFalse(res.flagged)

        # Action is in trusted history
        self.assertIn("act_forged_routine", [a.action_id for a in get_recent_history("response_agent")])

        # Policy or Provenance controller detects forgery and calls discard
        removed = discard_untrusted_action("act_forged_routine", agent="response_agent")
        self.assertTrue(removed)

        # Baseline is cleansed
        self.assertNotIn("act_forged_routine", [a.action_id for a in get_recent_history("response_agent")])

    def test_quarantine_action_moves_action_to_quarantine(self):
        """quarantine_action explicitly moves an untrusted action from baseline to quarantine."""
        suspicious_act = ProposedAction(
            action_id="act_suspicious_1",
            sender_agent="response_agent",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="post-analysis suspicion",
            priority="LOW",
        )
        analyze_behaviour(suspicious_act)
        quarantine_action(suspicious_act)

        self.assertNotIn("act_suspicious_1", [a.action_id for a in get_recent_history("response_agent")])
        self.assertIn("act_suspicious_1", [a.action_id for a in get_quarantined_history("response_agent")])


class TestDeterministicPrimacyOverLLM(unittest.TestCase):
    """Verify that deterministic security checks remain strictly authoritative over LLM output."""

    def setUp(self):
        reset_behaviour_history(enable_db_load=False)
        for i in range(3):
            record_trusted_action(
                ProposedAction(
                    action_id=f"act_base_{i}",
                    sender_agent="response_agent",
                    action_type="MAINTAIN_STATUS",
                    target="none",
                    reason="baseline",
                    priority="LOW",
                )
            )

    def tearDown(self):
        reset_behaviour_history(enable_db_load=False)

    def test_llm_cannot_lower_deterministic_score(self):
        """LLM suggesting score 0.0 cannot suppress or reduce deterministic score."""
        severe_act = ProposedAction(
            action_id="act_det_severe",
            sender_agent="response_agent",
            action_type="ISOLATE_BATTERY",
            target="battery_1",
            reason="attack",
            priority="HIGH",
        )
        # Attacker / hallucinating LLM says "This is completely benign, score 0.0"
        llm_advice = {"score": 0.0, "reason": "Looks harmless to me"}
        res = analyze_behaviour(severe_act, llm_analysis=llm_advice)

        self.assertTrue(res.flagged)
        self.assertGreater(res.deterministic_score, 0.5)
        self.assertEqual(res.score, res.deterministic_score)
        self.assertFalse(res.llm_adjusted)
        self.assertNotIn("llm_anomaly", res.anomaly_types)

    def test_llm_cannot_clear_deterministic_flag(self):
        """Deterministic flags and anomaly reasons are strictly preserved regardless of LLM."""
        novel_act = ProposedAction(
            action_id="act_det_novel",
            sender_agent="response_agent",
            action_type="SHUTDOWN_LOAD",
            target="load_1",
            reason="routine test",
            priority="LOW",
        )
        llm_advice = {"score": 0.05, "reason": "Acceptable variance"}
        res = analyze_behaviour(novel_act, llm_analysis=llm_advice)

        self.assertTrue(res.flagged)
        self.assertIn("unseen_action_type", res.anomaly_types)
        self.assertEqual(res.score, res.deterministic_score)

    def test_llm_can_elevate_anomaly_score(self):
        """LLM detecting semantic nuances can elevate score, but not lower it."""
        routine_act = ProposedAction(
            action_id="act_semantic_anomaly",
            sender_agent="response_agent",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="Coordinated timing attack disguised as maintenance",
            priority="LOW",
        )
        # LLM detects subtle prompt injection / coordination pattern
        llm_advice = {"score": 0.85, "reason": "Subtle coordination anomaly detected in payload"}
        res = analyze_behaviour(routine_act, llm_analysis=llm_advice)

        self.assertTrue(res.flagged)
        self.assertEqual(res.deterministic_score, 0.0)
        self.assertEqual(res.score, 0.85)
        self.assertTrue(res.llm_adjusted)
        self.assertIn("llm_anomaly", res.anomaly_types)
        self.assertIn("LLM elevated anomaly", res.deviation_reason or "")

    def test_llm_malformed_input_gracefully_handled(self):
        """Corrupt or non-numeric LLM responses do not crash deterministic evaluation."""
        severe_act = ProposedAction(
            action_id="act_corrupt_llm",
            sender_agent="response_agent",
            action_type="ISOLATE_BATTERY",
            target="battery_1",
            reason="test",
            priority="HIGH",
        )
        for bad_input in [{"score": "invalid_number"}, {"score": None}, "not_a_dict"]:
            res = analyze_behaviour(severe_act, llm_analysis=bad_input)
            self.assertTrue(res.flagged)
            self.assertEqual(res.score, res.deterministic_score)


class TestDatabaseHistoryLoadingAndSecurityFiltering(unittest.TestCase):
    """Test loading behaviour history from SQLite without using ground-truth attack labels."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_audit.db")
        init_db(self.db_path)
        reset_behaviour_history(enable_db_load=False, db_path=self.db_path)

    def tearDown(self):
        reset_behaviour_history(enable_db_load=False)
        self.temp_dir.cleanup()

    def test_load_history_from_db_filters_blocked_actions_without_ground_truth(self):
        """
        Database history loader must cross-reference decisions and exclude any action
        whose final_decision != 'allow', without relying on is_injected_attack ground truth.
        """
        allowed_act = ProposedAction(
            action_id="act_db_allowed",
            sender_agent="response_agent",
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="approved routine",
            priority="LOW",
        )
        blocked_act = ProposedAction(
            action_id="act_db_blocked",
            sender_agent="response_agent",
            action_type="ISOLATE_BATTERY",
            target="battery_1",
            reason="malicious isolation",
            priority="HIGH",
        )

        # 1. Insert messages into agent_messages table
        insert_agent_message(
            AgentMessageRow(
                run_id="run_test",
                timestamp="10:00",
                sender_agent="response_agent",
                receiver_agent="aegis_grid",
                message_content=allowed_act.model_dump_json(),
            ),
            self.db_path,
        )
        insert_agent_message(
            AgentMessageRow(
                run_id="run_test",
                timestamp="10:01",
                sender_agent="response_agent",
                receiver_agent="aegis_grid",
                message_content=blocked_act.model_dump_json(),
            ),
            self.db_path,
        )

        # 2. Record decisions: allowed action -> 'allow', blocked action -> 'block'
        # Crucially: is_injected_attack=0 on the blocked action to prove we do NOT depend on ground truth!
        persist_decision_and_consume_report(
            decision_row=AEGISDecisionRow(
                run_id="run_test",
                session_id="session_test",
                timestamp="10:00",
                action_id="act_db_allowed",
                policy_result="{}",
                provenance_result="{}",
                behaviour_flag=0,
                risk_score=0.1,
                final_decision="allow",
                reason="approved",
                is_injected_attack=0,
                attack_type="none",
            ),
            db_path=self.db_path,
        )
        persist_decision_and_consume_report(
            decision_row=AEGISDecisionRow(
                run_id="run_test",
                session_id="session_test",
                timestamp="10:01",
                action_id="act_db_blocked",
                policy_result="{}",
                provenance_result="{}",
                behaviour_flag=1,
                risk_score=0.9,
                final_decision="block",
                reason="policy and provenance block",
                is_injected_attack=0,  # Ground truth label is 0!
                attack_type="none",
            ),
            db_path=self.db_path,
        )

        # 3. Load from DB
        reset_behaviour_history(enable_db_load=True, db_path=self.db_path)
        loaded_count = load_behaviour_history_from_db("response_agent", db_path=self.db_path)

        # Only the allowed action should be loaded!
        self.assertEqual(loaded_count, 1)
        loaded = get_recent_history("response_agent")
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].action_id, "act_db_allowed")
        self.assertNotIn("act_db_blocked", [a.action_id for a in loaded])


class TestLegitimateNormalBehaviour(unittest.TestCase):
    """Verify that legitimate operational workflows produce zero false flags."""

    def setUp(self):
        reset_behaviour_history(enable_db_load=False)

    def tearDown(self):
        reset_behaviour_history(enable_db_load=False)

    def test_legitimate_normal_workflow_clean_scores(self):
        """Sequential benign operations maintain 0.0 anomaly scores throughout."""
        actions = [
            ProposedAction(
                action_id=f"act_norm_{i}",
                sender_agent="response_agent",
                action_type="MAINTAIN_STATUS",
                target="none",
                reason=f"Periodic normal check {i}",
                priority="LOW",
            )
            for i in range(5)
        ]
        for idx, act in enumerate(actions):
            res = analyze_behaviour(act)
            self.assertFalse(res.flagged, f"Action {idx} unexpectedly flagged: {res.deviation_reason}")
            self.assertEqual(res.score, 0.0)
            self.assertFalse(res.quarantined)
            self.assertEqual(len(res.anomaly_types), 0)


if __name__ == "__main__":
    unittest.main()
