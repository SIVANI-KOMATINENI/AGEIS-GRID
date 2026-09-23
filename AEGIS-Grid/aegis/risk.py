"""
aegis/risk.py
Risk Evaluation Stage.
Combines Policy, Provenance, and Behaviour results into a unified Risk Score.
"""

from typing import Dict
from pydantic import BaseModel

import config as cfg
from aegis.policy import PolicyResult
from aegis.provenance import ProvenanceResult
from aegis.behaviour import BehaviourResult


class RiskResult(BaseModel):
    stage: str = "risk"
    score: float       # 0.0 to 1.0
    band: str          # "LOW", "MEDIUM", "HIGH"
    contributing_factors: Dict[str, float]


def evaluate_risk(
    policy_res: PolicyResult, 
    prov_res: ProvenanceResult, 
    behav_res: BehaviourResult
) -> RiskResult:
    """
    Weighted sum equation:
    Risk = (Policy Penalty * w1) + (Provenance Penalty * w2) + (Behaviour Penalty * w3)
    """
    
    # 1. Base Penalties (0.0 means good, 1.0 means full violation/risk)
    policy_penalty = 1.0 if policy_res.decision == "block" else 0.0
    
    # Provenance penalty: full penalty if verified=False.
    # If the policy allows it without auth, provenance sets verified=True.
    prov_penalty = 0.0 if prov_res.verified else 1.0
    
    behav_penalty = 1.0 if behav_res.flagged else 0.0
    
    # 2. Apply configuration weights
    w_pol = cfg.RISK_WEIGHT_POLICY
    w_pro = cfg.RISK_WEIGHT_PROVENANCE
    w_beh = cfg.RISK_WEIGHT_BEHAVIOUR
    
    score = (policy_penalty * w_pol) + (prov_penalty * w_pro) + (behav_penalty * w_beh)
    
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
            "behaviour": float(behav_penalty * w_beh)
        }
    )

if __name__ == "__main__":
    r = evaluate_risk(
        PolicyResult(decision="allow", reason=""),
        ProvenanceResult(verified=False, trace_length=0, reason=""),
        BehaviourResult(flagged=True)
    )
    print(r.model_dump_json(indent=2))
