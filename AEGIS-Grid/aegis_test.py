"""
aegis_test.py - Milestone 4 verification script.
Tests the pipeline.
"""
import sys
from pathlib import Path

# Ensure project root is on path
_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))

from agents.schemas import ProposedAction
from aegis.policy import verify_policy
from aegis.provenance import verify_provenance
from aegis.behaviour import analyze_behaviour, reset_behaviour_history
from aegis.risk import evaluate_risk
from aegis.controller import make_decision

def run_pipeline(action: ProposedAction):
    pol = verify_policy(action)
    prov = verify_provenance(action)
    beh = analyze_behaviour(action)
    risk = evaluate_risk(pol, prov, beh)
    decision = make_decision(action, pol, prov, beh, risk)
    return decision

def test():
    print("=" * 60)
    print("AEGIS Grid - Milestone 4: AEGIS Core Pipeline Test")
    print("=" * 60)
    reset_behaviour_history()

    print("\nTest 1: Normal Benign Action (EXPECT ALLOW)")
    act1 = ProposedAction(
        action_id="act1", action_type="MAINTAIN_STATUS", target="none", 
        reason="looks good", priority="LOW"
    )
    res1 = run_pipeline(act1)
    print(f" -> Decision: {res1.final_decision.upper()} | Reason: {res1.reason}")
    assert res1.final_decision == "allow"

    print("\nTest 2: Valid Emergency Action (EXPECT ALLOW)")
    act2 = ProposedAction(
        action_id="act2", action_type="ISOLATE_BATTERY", target="battery_1", 
        reason="Fire!", priority="HIGH", claimed_authorization="real_report_id"
    )
    # The neo4j test client isn't connected so verify_provenance returns True as a graceful fallback.
    # Therefore, this should pass. Behaviour check WILL flag it because HIGH priority wasn't seen before.
    # But because behaviour weight is 0.2, Risk = 0.2 -> LOW band -> ALLOW.
    res2 = run_pipeline(act2)
    print(f" -> Decision: {res2.final_decision.upper()} | Reason: {res2.reason}")
    print(f"    Risk Band: {res2.risk_result.band} (Score: {res2.risk_result.score})")
    assert res2.final_decision == "allow"

    print("\nTest 3: Missing Authority on severe action (EXPECT BLOCK)")
    act3 = ProposedAction(
        action_id="act3", action_type="ISOLATE_BATTERY", target="battery_1", 
        reason="Sneaky!", priority="HIGH", claimed_authorization="" # Missing!
    )
    res3 = run_pipeline(act3)
    print(f" -> Decision: {res3.final_decision.upper()} | Reason: {res3.reason}")
    assert res3.final_decision == "block"
    
    print("\nTest 4: Critical Load Shutdown (EXPECT BLOCK)")
    act4 = ProposedAction(
        action_id="act4", action_type="SHUTDOWN_LOAD", target="critical_load", 
        reason="Oops", priority="HIGH", claimed_authorization="report_xyz"
    )
    res4 = run_pipeline(act4)
    print(f" -> Decision: {res4.final_decision.upper()} | Reason: {res4.reason}")
    assert res4.final_decision == "block"

    print("\n[OK] All Milestone 4 pipeline tests passed!")

if __name__ == "__main__":
    test()
