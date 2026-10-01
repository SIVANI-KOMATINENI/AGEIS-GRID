"""
aegis/provenance.py
Provenance Verification Stage.
Queries neo4j to verify the claimed authorization.
"""

from typing import List, Dict, Any
from pydantic import BaseModel

from agents.schemas import ProposedAction
from provenance.neo4j_client import get_neo4j_client


class ProvenanceResult(BaseModel):
    stage: str = "provenance"
    verified: bool
    trace_length: int
    reason: str


def verify_provenance(action: ProposedAction) -> ProvenanceResult:
    """
    Checks that the claimed report is linked to this action in Neo4j.
    """
    auth = action.claimed_authorization

    if not auth:
        return ProvenanceResult(
            verified=False,
            trace_length=0,
            reason="Provenance verification failed: action has no claimed report."
        )

    neo = get_neo4j_client()
    if not neo.driver:
        return ProvenanceResult(
            verified=False,
            trace_length=0,
            reason="Provenance verification failed: Neo4j is unavailable."
        )

    status = neo.authorization_status(auth, action.action_id, action.run_id)

    if status == "verified":
        return ProvenanceResult(
            verified=True,
            trace_length=3,
            reason="Provenance verified: action is linked to the claimed report in Neo4j."
        )

    if status == "report_missing":
        reason = "Provenance verification failed: claimed report does not exist."
    elif status == "unlinked":
        reason = "Provenance verification failed: report exists but is not linked to this action."
    else:
        reason = "Provenance verification failed: complete action provenance could not be verified."

    return ProvenanceResult(
        verified=False,
        trace_length=0,
        reason=reason
    )

if __name__ == "__main__":
    test_action = ProposedAction(
        action_id="test2", action_type="TEST", target="test", reason="test", priority="HIGH",
        claimed_authorization="fake_report_123"
    )
    res = verify_provenance(test_action)
    print(res.model_dump_json(indent=2))
