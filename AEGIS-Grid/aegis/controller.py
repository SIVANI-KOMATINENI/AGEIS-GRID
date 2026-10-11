"""
aegis/controller.py
The Decision Controller. Aggregates all AEGIS elements to make the final determination.
"""

from typing import Optional
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
    run_id: str = ""


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
    A policy HUMAN_APPROVAL overrides a low risk score, but a HIGH risk score can still BLOCK it.
    Otherwise, it maps the risk band to the resolution action.
    """
    
    # 1. Hard Policy Overrides
    if policy_res.decision == "block":
        return FinalDecision(
            final_decision="block",
            reason=f"Policy Override: {policy_res.reason}",
            action=action, policy_result=policy_res, provenance_result=prov_res, 
            behaviour_result=behav_res, risk_result=risk_res,
            run_id=action.run_id,
        )

    # 2. Hard Replay Override (replays must never be allowed or escalated to human approval)
    if getattr(risk_res, "replay_detected", False):
        return FinalDecision(
            final_decision="block",
            reason="Blocked due to detected replay attack on observation telemetry.",
            action=action, policy_result=policy_res, provenance_result=prov_res,
            behaviour_result=behav_res, risk_result=risk_res,
            run_id=action.run_id,
        )

    # 3. Hard Provenance / Authority Invalidation Gate
    # Forged, mismatched, reused, or unauthorized credentials must always be denied
    if not prov_res.verified:
        if (
            getattr(prov_res, "auth_type", None) == "personnel"
            or getattr(prov_res, "status", None) in (
                "invalid_claim",
                "mismatched_run_id",
                "mismatched_session_id",
                "report_reused",
                "credential_reused",
                "unauthorized_action",
                "unauthorized_target",
                "action_digest_mismatch",
                "unknown_personnel",
                "missing_signature",
                "invalid_signature",
                "revoked_credential",
                "expired_credential",
                "priority_exceeded",
                "parameter_exceeded",
                "missing_co_approval",
                "invalid_co_signer",
                "missing_credential",
                "unverified_personnel",
            )
        ):
            return FinalDecision(
                final_decision="block",
                reason=f"Provenance Denied: {prov_res.reason}",
                action=action, policy_result=policy_res, provenance_result=prov_res,
                behaviour_result=behav_res, risk_result=risk_res,
                run_id=action.run_id,
            )

    # 4. Risk Score Mapping
    if risk_res.band == "HIGH":
        decision = "block"
        reason = "Blocked due to HIGH aggregate risk score."
    elif risk_res.band == "MEDIUM" or policy_res.decision == "human_approval":
        # If policy demands human approval, we do it even if risk is low (as long as it wasn't blocked above)
        decision = "human_approval"
        if policy_res.decision == "human_approval":
             reason = f"Escalated for human approval due to Policy: {policy_res.reason}"
        else:
             reason = "Escalated for human approval due to MEDIUM aggregate risk score."
    else:
        # Invariant: An action must NEVER be allowed unless provenance is verified
        if not prov_res.verified:
            decision = "human_approval"
            reason = f"Escalated for human approval (Fail-Closed): Provenance not verified ({prov_res.reason})"
        else:
            decision = "allow"
            reason = "Action approved. Low risk and policy compliant."

    return FinalDecision(
        final_decision=decision,
        reason=reason,
        action=action, policy_result=policy_res, provenance_result=prov_res, 
        behaviour_result=behav_res, risk_result=risk_res,
        run_id=action.run_id,
    )
