"""
aegis/risk.py
Risk Evaluation Stage.
Combines Policy, Provenance, and Behaviour results into a unified Risk Score.
Uses continuous scoring logic.
"""

from typing import Dict, Optional
from pydantic import BaseModel

import config as cfg
from aegis.policy import PolicyResult
from aegis.provenance import ProvenanceResult
from aegis.behaviour import BehaviourResult
from database.models import ReplayCheckResult


class RiskResult(BaseModel):
    stage: str = "risk"
    score: float       # 0.0 to 1.0
    band: str          # "LOW", "MEDIUM", "HIGH"
    contributing_factors: Dict[str, float]
    replay_detected: bool = False


def evaluate_risk(
    policy_res: PolicyResult, 
    prov_res: ProvenanceResult, 
    behav_res: BehaviourResult,
    replay_result: Optional[ReplayCheckResult] = None,
) -> RiskResult:
    """
    Weighted sum equation using continuous penalties.
    Risk = (Policy Penalty * w1) + (Provenance Penalty * w2) + (Behaviour Penalty * w3)
    """
    
    # 1. Base Penalties (0.0 means good, 1.0 means full violation/risk)
    
    # Policy penalty: 
    if policy_res.decision == "block":
        policy_penalty = 1.0
    elif policy_res.decision == "human_approval":
        policy_penalty = 0.5
    else:
        policy_penalty = 0.0
    
    # Provenance penalty: full penalty if verified=False.
    # If the policy allows it without auth, provenance sets verified=True.
    prov_penalty = 0.0 if prov_res.verified else 1.0
    
    # Behaviour penalty is now directly mapped to the calculated score
    behav_penalty = behav_res.score
    replay_detected = bool(replay_result and replay_result.detected)
    
    # 2. Apply configuration weights
    w_pol = cfg.RISK_WEIGHT_POLICY
    w_pro = cfg.RISK_WEIGHT_PROVENANCE
    w_beh = cfg.RISK_WEIGHT_BEHAVIOUR
    
    score = (policy_penalty * w_pol) + (prov_penalty * w_pro) + (behav_penalty * w_beh)
    
    # A replay is a direct security signal; map it into the existing HIGH-risk
    # path so the existing Decision Controller returns BLOCK.
    if replay_detected:
        score = 1.0

    # Normalise score to exactly 0..1 to prevent floating point drift
    score = max(0.0, min(1.0, score))
    
    # 3. Determine Band
    if score >= cfg.RISK_BAND_HIGH:
        band = "HIGH"
    elif score >= cfg.RISK_BAND_MEDIUM:
        band = "MEDIUM"
    else:
        band = "LOW"
        
    return RiskResult(
        score=round(score, 3),
        band=band,
        contributing_factors={
            "policy": float(policy_penalty * w_pol),
            "provenance": float(prov_penalty * w_pro),
            "behaviour": float(behav_penalty * w_beh),
            "replay": 1.0 if replay_detected else 0.0,
        },
        replay_detected=replay_detected,
    )

if __name__ == "__main__":
    r = evaluate_risk(
        PolicyResult(decision="allow", reason=""),
        ProvenanceResult(verified=False, trace_length=0, reason=""),
        BehaviourResult(flagged=True, score=0.7)
    )
    print(r.model_dump_json(indent=2))
