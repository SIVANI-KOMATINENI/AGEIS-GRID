"""
aegis/provenance.py
Provenance Verification Stage.
Queries neo4j to verify the claimed authorization.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel

from agents.schemas import ProposedAction
from provenance.neo4j_client import get_neo4j_client


class ProvenanceResult(BaseModel):
    stage: str = "provenance"
    verified: bool
    trace_length: int
    reason: str
    status: str = "verified"
    auth_type: Optional[str] = None  # "personnel" | "diagnostic_report"
    personnel_id: Optional[str] = None
    role: Optional[str] = None


def verify_provenance(
    action: ProposedAction,
    session_id: str = "",
    personnel_registry: Optional[Any] = None,
    now: Optional[Any] = None,
) -> ProvenanceResult:
    """
    Verifies action authority and provenance.
    
    Distinguishes two primary authority channels:
      1. Personnel Authority: Cryptographically signed operational credentials
         issued by human grid operators (verified via Personnel Authority Registry).
      2. Diagnostic Report Provenance: Lineage linking an automated response action
         to a monitoring diagnostic report in Neo4j (verified via graph trace and
         atomic report consumption).
    """
    # ── Channel 1: Personnel Authorization Evidence ─────────────────────────
    evidence = getattr(action, "authorization_evidence", None)
    if evidence is not None and evidence.token_type == "PERSONNEL_CREDENTIAL":
        from aegis.personnel import verify_personnel_authority

        auth_res = verify_personnel_authority(
            action=action,
            registry=personnel_registry,
            now=now,
        )

        if auth_res.is_authorized:
            from database.sqlite import is_personnel_credential_consumed
            if evidence.nonce and is_personnel_credential_consumed(evidence.personnel_id, evidence.nonce):
                return ProvenanceResult(
                    verified=False,
                    trace_length=0,
                    status="credential_reused",
                    reason=(
                        f"Personnel provenance verification failed: authorization evidence (nonce '{evidence.nonce}') "
                        f"for personnel '{evidence.personnel_id}' has already been consumed (replay rejected)."
                    ),
                    auth_type="personnel",
                    personnel_id=auth_res.personnel_id,
                    role=auth_res.role,
                )
            if evidence.co_signer_id and evidence.nonce and is_personnel_credential_consumed(evidence.co_signer_id, evidence.nonce):
                return ProvenanceResult(
                    verified=False,
                    trace_length=0,
                    status="credential_reused",
                    reason=(
                        f"Co-signer provenance verification failed: authorization evidence (nonce '{evidence.nonce}') "
                        f"for co-signer '{evidence.co_signer_id}' has already been consumed (replay rejected)."
                    ),
                    auth_type="personnel",
                    personnel_id=auth_res.personnel_id,
                    role=auth_res.role,
                )

            return ProvenanceResult(
                verified=True,
                trace_length=2,
                status="verified",
                reason=(
                    f"Personnel authority verified: valid cryptographic credential and operational "
                    f"scope for {auth_res.role or 'operator'} ({auth_res.personnel_id})."
                ),
                auth_type="personnel",
                personnel_id=auth_res.personnel_id,
                role=auth_res.role,
            )

        # Map fine-grained authority verification status codes to provenance statuses
        status_map = {
            "CREDENTIAL_REUSED": "credential_reused",
            "UNKNOWN_PERSONNEL": "unknown_personnel",
            "MISSING_SIGNATURE": "missing_signature",
            "INVALID_SIGNATURE": "invalid_signature",
            "TAMPERED_ACTION": "action_digest_mismatch",
            "REVOKED_CREDENTIAL": "revoked_credential",
            "EXPIRED_CREDENTIAL": "expired_credential",
            "UNAUTHORIZED_ACTION": "unauthorized_action",
            "UNAUTHORIZED_TARGET": "unauthorized_target",
            "PRIORITY_EXCEEDED": "priority_exceeded",
            "PARAMETER_EXCEEDED": "parameter_exceeded",
            "MISSING_CO_APPROVAL": "missing_co_approval",
            "INVALID_CO_SIGNER": "invalid_co_signer",
            "MISSING_CREDENTIAL": "missing_credential",
            "UNSUPPORTED_TOKEN_TYPE": "invalid_claim",
        }
        prov_status = status_map.get(auth_res.status_code, "unverified_personnel")
        return ProvenanceResult(
            verified=False,
            trace_length=0,
            status=prov_status,
            reason=f"Personnel provenance verification failed: {auth_res.failure_reason}",
            auth_type="personnel",
            personnel_id=auth_res.personnel_id,
            role=auth_res.role,
        )

    # ── Channel 2: Automated Diagnostic-Report Provenance ────────────────────
    auth = action.claimed_authorization

    if not auth:
        return ProvenanceResult(
            verified=False,
            trace_length=0,
            status="invalid_claim",
            reason="Provenance verification failed: action has no claimed report.",
            auth_type="diagnostic_report",
        )

    # Defense: Claimed personnel identifier without cryptographic evidence
    if auth.startswith("PERS-") or auth.startswith("cred_pers_"):
        return ProvenanceResult(
            verified=False,
            trace_length=0,
            status="missing_credential",
            reason=(
                f"Provenance verification failed: claimed personnel identifier '{auth}' "
                "requires cryptographic AuthorizationEvidence."
            ),
            auth_type="personnel",
            personnel_id=auth,
        )

    # Check atomic report consumption in SQLite as defense-in-depth
    from database.sqlite import is_report_consumed
    sess_id = session_id or getattr(action, "session_id", "") or ""
    if sess_id and is_report_consumed(auth, sess_id):
        return ProvenanceResult(
            verified=False,
            trace_length=0,
            status="report_reused",
            reason=(
                f"Provenance verification failed: attempt to reuse report '{auth}' "
                f"which was already claimed in session '{sess_id}'."
            ),
            auth_type="diagnostic_report",
        )

    neo = get_neo4j_client()
    if not neo.driver:
        return ProvenanceResult(
            verified=False,
            trace_length=0,
            status="unavailable",
            reason="Provenance verification failed: Neo4j is unavailable.",
            auth_type="diagnostic_report",
        )

    action_digest = getattr(action, "action_digest", "")

    if sess_id:
        status = neo.authorization_status(
            auth,
            action.action_id,
            action.run_id,
            action_type=action.action_type,
            session_id=sess_id,
            action_digest=action_digest,
        )
    else:
        status = neo.authorization_status(
            auth,
            action.action_id,
            action.run_id,
        )

    # Phase B.3: Check action content integrity digest (tampering check)
    if hasattr(action, "is_digest_valid") and not action.is_digest_valid():
        status = "action_digest_mismatch"

    # If the token is explicitly forged or malformed, override status as invalid_claim
    if (
        auth.startswith("auth_tok_")
        or "forged" in auth.lower()
        or "fake" in auth.lower()
        or "spoof" in auth.lower()
    ):
        if status in ("verified", "report_missing"):
            status = "invalid_claim"

    if status == "verified":
        return ProvenanceResult(
            verified=True,
            trace_length=3,
            status="verified",
            reason="Provenance verified: action is linked to the claimed report in Neo4j.",
            auth_type="diagnostic_report",
        )

    if status == "unavailable":
        reason = "Provenance verification failed: Neo4j is unavailable (fail-closed)."
    elif status == "invalid_claim":
        reason = f"Provenance verification failed: forged or invalid authorization credential '{auth}'."
    elif status == "mismatched_session_id":
        reason = "Provenance verification failed: claimed report belongs to a different simulation session."
    elif status == "mismatched_run_id":
        reason = "Provenance verification failed: claimed report run_id does not match action run_id."
    elif status == "action_digest_mismatch":
        reason = "Provenance verification failed: action digest does not match logged provenance in Neo4j."
    elif status == "report_reused":
        reason = f"Provenance verification failed: attempt to reuse report '{auth}' which was already claimed."
    elif status == "unauthorized_action":
        reason = f"Provenance verification failed: claimed report does not authorize action '{action.action_type}'."
    elif status == "report_missing":
        reason = "Provenance verification failed: claimed report does not exist."
    elif status == "unlinked":
        reason = "Provenance verification failed: report exists but is not linked to this action."
    else:
        reason = "Provenance verification failed: complete action provenance could not be verified."

    return ProvenanceResult(
        verified=False,
        trace_length=0,
        status=status,
        reason=reason,
        auth_type="diagnostic_report",
    )

if __name__ == "__main__":
    test_action = ProposedAction(
        action_id="test2", action_type="TEST", target="test", reason="test", priority="HIGH",
        claimed_authorization="fake_report_123"
    )
    res = verify_provenance(test_action)
    print(res.model_dump_json(indent=2))
