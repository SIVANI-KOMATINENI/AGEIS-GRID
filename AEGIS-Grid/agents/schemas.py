"""
agents/schemas.py
Pydantic schemas for the inputs and outputs of the Monitoring and Response agents.
"""

from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field


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


class ProposedAction(BaseModel):
    action_id: str = Field(
        description="Unique ID for this action proposal, e.g. act_13:30"
    )

    run_id: str = Field(
        default="",
        description="Workflow execution identifier inherited from the report",
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