"""
database/models.py
Pydantic models for each database row / structured data exchange.
These are used for type-safe inserts into SQLite and as shared data contracts.
"""

from __future__ import annotations
from typing import Optional
from pydantic import BaseModel, Field


# ── SQLite Row Models ─────────────────────────────────────────────────────────

class ObservationRow(BaseModel):
    """Maps to the `observations` SQLite table."""
    run_id: Optional[str] = None
    timestamp: str
    voltage_pu: float
    load_kw: float
    solar_kw: float
    battery_soc_pct: float
    battery_temperature_c: float
    transformer_loading_pct: float


class AgentMessageRow(BaseModel):
    """Maps to the `agent_messages` SQLite table."""
    run_id: Optional[str] = None
    timestamp: str
    sender_agent: str
    receiver_agent: str
    message_content: str   # JSON-serialized payload


class AttackEventRow(BaseModel):
    """Maps to the `attack_events` SQLite table."""
    run_id: Optional[str] = None
    attack_type: str
    target: str
    start_time: str
    end_time: str
    ground_truth: int = 1  # always 1 for real injected attacks


class AEGISDecisionRow(BaseModel):
    """Maps to the `aegis_decisions` SQLite table."""
    run_id: Optional[str] = None
    timestamp: str
    action_id: str
    policy_result: str          # JSON-serialized PolicyResult
    provenance_result: str       # JSON-serialized ProvenanceResult
    behaviour_flag: int          # 0 or 1
    risk_score: float
    final_decision: str          # "allow" | "block" | "human_approval"
    reason: str
    human_reviewer: Optional[str] = None
    is_injected_attack: int = 0  # ground truth (1 if injected attack)
    attack_type: Optional[str] = None  # ground truth attack type
