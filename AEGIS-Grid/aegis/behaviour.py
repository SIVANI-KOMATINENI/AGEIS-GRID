"""
aegis/behaviour.py
Behaviour Analysis Stage.
Simple historical sliding window check to flag erratic agent behaviour.
"""

from typing import List, Optional
from pydantic import BaseModel

from agents.schemas import ProposedAction
import config as cfg

class BehaviourResult(BaseModel):
    stage: str = "behaviour"
    flagged: bool
    deviation_reason: Optional[str] = None


# State dictionary holding typical recent behaviour (in a real app, query SQLite)
# Format: { "agent_name": [action1, action2, ... ] }
_recent_history = {}


def reset_behaviour_history():
    """Clear memory (useful for testing eval grids)"""
    global _recent_history
    _recent_history = {}


def analyze_behaviour(action: ProposedAction) -> BehaviourResult:
    """
    Flags the action if:
    - This specific action_type has never been proposed by this agent recently.
    - The priority jumps suddenly (e.g. they only ever do LOW/MAINTAIN, but suddenly request HIGH/SHUTDOWN).
    """
    agent = action.sender_agent
    
    if agent not in _recent_history:
        _recent_history[agent] = []
        
    history = _recent_history[agent]
    
    # 1. New Agent (no baseline yet)
    if not history:
        _recent_history[agent].append(action)
        return BehaviourResult(
            flagged=False,
            deviation_reason="No baseline history yet; passing by default."
        )

    # Calculate baselines
    past_types = set([a.action_type for a in history])
    past_priorities = set([a.priority for a in history])
    
    flagged = False
    reasons = []

    # Check 1: Unseen action type
    if action.action_type not in past_types:
        flagged = True
        reasons.append(f"Action '{action.action_type}' never seen in recent history.")
        
    # Check 2: Severe escalation (only did LOW/MAINTAIN recently, now proposing HIGH)
    if action.priority == "HIGH" and "HIGH" not in past_priorities and "MEDIUM" not in past_priorities:
        flagged = True
        reasons.append("Sudden escalation to HIGH priority without prior MEDIUM warnings.")
        
    # Update memory
    _recent_history[agent].append(action)
    if len(_recent_history[agent]) > cfg.BEHAVIOUR_HISTORY_SIZE:
        _recent_history[agent].pop(0)
        
    return BehaviourResult(
        flagged=flagged,
        deviation_reason=" | ".join(reasons) if flagged else None
    )

if __name__ == "__main__":
    act1 = ProposedAction(action_id="1", action_type="MAINTAIN_STATUS", target="none", reason="test", priority="LOW")
    act2 = ProposedAction(action_id="2", action_type="ISOLATE_BATTERY", target="battery1", reason="test", priority="HIGH")
    
    print("Action 1:", analyze_behaviour(act1)) # false
    print("Action 2:", analyze_behaviour(act2)) # flags true (never seen ISOLATE_BATTERY or HIGH)
