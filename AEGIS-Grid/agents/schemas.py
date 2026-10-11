"""
agents/schemas.py
Pydantic schemas for the inputs and outputs of the Monitoring and Response agents.
"""

import hashlib
import json
from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field


def compute_action_digest(
    action_type: str,
    target: str,
    parameters: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Computes a canonical SHA-256 hex digest of the action content.
    Uses deterministic JSON serialization with sorted keys so equivalent
    parameter objects produce identical digests.

    Security Note:
        This is an unkeyed cryptographic digest intended for content integrity
        verification against tampering/mutation in memory or in transit.
        It does not serve as an authentication token or digital signature;
        an attacker with arbitrary write privileges to both the payload and
        graph could compute a matching hash.
    """
    canonical_payload = {
        "action_type": str(action_type or "").strip().upper(),
        "target": str(target or "").strip().lower(),
        "parameters": parameters or {},
    }
    canonical_json = json.dumps(
        canonical_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()



# ── Monitoring Agent IO ───────────────────────────────────────────────────────

class MonitoringInput(BaseModel):
    current: Dict[str, Any]
    recent_history: List[Dict[str, Any]]
    context: Dict[str, Any]


class MonitoringReport(BaseModel):
    agent: str = Field(default="monitoring_agent")
    run_id: str = Field(
        default="",
        description="Unique identifier for the workflow execution",
    )
    session_id: str = Field(
        default="",
        description="Simulation session boundary",
    )
    report_id: str = Field(
        description="Stable identifier for this diagnostic report"
    )
    timestamp: str = Field(
        description="The timestamp of the observation being analysed"
    )
    status: str = Field(
        description="Either 'NORMAL' or 'ANOMALY'"
    )
    severity: str = Field(
        description="Either 'LOW', 'MEDIUM', 'HIGH', or 'NONE'"
    )
    issue: Optional[str] = Field(
        None,
        description="Brief description of the anomaly, or null if normal"
    )
    evidence: Dict[str, Any] = Field(
        default_factory=dict,
        description="Key metrics justifying the report"
    )
    recommended_action: Optional[str] = Field(
        None,
        description="General advice for the Response Agent"
    )
    confidence: float = Field(
        description="Agent confidence from 0.0 to 1.0"
    )


# ── Response Agent IO ─────────────────────────────────────────────────────────

class ResponseInput(BaseModel):
    diagnostic_report: MonitoringReport
    current_state: Dict[str, Any]


class AuthorizationEvidence(BaseModel):
    token_type: Literal[
        "DIAGNOSTIC_REPORT",
        "PERSONNEL_CREDENTIAL"
    ] = Field(
        default="PERSONNEL_CREDENTIAL",
        description="Type of authorization evidence provided.",
    )

    personnel_id: Optional[str] = Field(
        default=None,
        description="Claimed personnel identifier, e.g. PERS-001.",
    )

    signature: Optional[str] = Field(
        default=None,
        description="Cryptographic signature over canonical authorization payload.",
    )

    issued_at: Optional[str] = Field(
        default=None,
        description="ISO-8601 timestamp when authorization was issued.",
    )

    nonce: Optional[str] = Field(
        default=None,
        description="Cryptographic nonce to tie authorization to a single action execution.",
    )

    co_signer_id: Optional[str] = Field(
        default=None,
        description="Personnel ID of co-authorizing party when co-approval is required.",
    )

    co_signer_signature: Optional[str] = Field(
        default=None,
        description="Cryptographic signature of co-signer.",
    )

    action_id: Optional[str] = Field(
        default=None,
        description="Action proposal ID explicitly bound to this authorization evidence.",
    )

    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional operational metadata (e.g. work ticket ID, notes).",
    )


class ProposedAction(BaseModel):
    action_id: str = Field(
        description="Unique ID for this action proposal, e.g. act_13:30"
    )

    run_id: str = Field(
        default="",
        description="Workflow execution identifier inherited from the report",
    )

    session_id: str = Field(
        default="",
        description="Simulation session boundary",
    )

    sender_agent: str = Field(
        default="response_agent"
    )

    action_type: Literal[
        "ISOLATE_BATTERY",
        "REDUCE_LOAD",
        "SHUTDOWN_LOAD",
        "MAINTAIN_STATUS",
        "INSPECT",
        "LOG_WARNING",
        "INVESTIGATE"
    ] = Field(
        description="The action proposed by the Response Agent"
    )

    target: Literal[
        "battery_1",
        "critical_load",
        "load_1",
        "none",
        "unknown"
    ] = Field(
        description=(
            "Target component. Must be one of: "
            "battery_1, critical_load, load_1, none, unknown."
        )
    )

    reason: str = Field(
        description="Why this action is proposed"
    )

    priority: Literal[
        "LOW",
        "MEDIUM",
        "HIGH"
    ] = Field(
        description="Action priority"
    )

    claimed_authorization: Optional[str] = Field(
        None,
        description=(
            "Report ID or authorization token that justifies "
            "this action."
        )
    )

    authorization_evidence: Optional[AuthorizationEvidence] = Field(
        default=None,
        description=(
            "Cryptographically verifiable personnel or report "
            "authorization evidence."
        )
    )

    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Action parameters and setpoints",
    )

    action_digest: str = Field(
        default="",
        description="Canonical SHA-256 digest of action content (action_type, target, parameters)",
    )

    def model_post_init(self, __context: Any) -> None:
        if not self.action_digest:
            self.action_digest = compute_action_digest(
                self.action_type, self.target, self.parameters
            )

    def is_digest_valid(self) -> bool:
        """Verifies that the stored digest matches the canonical hash of current action content."""
        return self.action_digest == compute_action_digest(
            self.action_type, self.target, self.parameters
        )