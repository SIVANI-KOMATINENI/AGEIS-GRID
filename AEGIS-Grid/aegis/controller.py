"""
aegis/controller.py
The Decision Controller. Aggregates all AEGIS elements to make the final determination.
"""

from typing import Optional
# pyrefly: ignore [missing-import]
from pydantic import BaseModel

from agents.schemas import ProposedAction
from aegis.policy import PolicyResult
from aegis.provenance import ProvenanceResult
from aegis.behaviour import BehaviourResult
from aegis.risk import RiskResult


class FinalDecision(BaseModel):
    final_decision: str   # "allow" | "block" | "human_approval"
    reason: str
    action: ProposedAction
    policy_result: PolicyResult
    provenance_result: ProvenanceResult
    behaviour_result: BehaviourResult
    risk_result: RiskResult


def make_decision(
    action: ProposedAction,
    policy_res: PolicyResult,
    prov_res: ProvenanceResult,
    behav_res: BehaviourResult,
    risk_res: RiskResult
) -> FinalDecision:
    """
    Final Logic Gate.
    A hard policy BLOCK overrides a low risk score.
    Otherwise, it maps the risk band to the resolution action.
    """
    
    # 1. Hard Policy Overrides
    if policy_res.decision == "block":
        return FinalDecision(
            final_decision="block",
            reason=f"Policy Override: {policy_res.reason}",
            action=action, policy_result=policy_res, provenance_result=prov_res, 
            behaviour_result=behav_res, risk_result=risk_res
        )
        
    # 2. Risk Score Mapping
    if risk_res.band == "HIGH":
        decision = "block"
        reason = "Blocked due to HIGH aggregate risk score."
    elif risk_res.band == "MEDIUM":
        decision = "human_approval"
        reason = "Escalated for human approval due to MEDIUM aggregate risk score."
    else:
        decision = "allow"
        reason = "Action approved. Low risk and policy compliant."

    return FinalDecision(
        final_decision=decision,
        reason=reason,
        action=action, policy_result=policy_res, provenance_result=prov_res, 
        behaviour_result=behav_res, risk_result=risk_res
    )
