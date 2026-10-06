"""
aegis/behaviour.py
Behaviour Analysis Stage.
Historical sliding window check to flag erratic agent behaviour.
Outputs a continuous anomaly score.
"""

from typing import List, Optional
from pydantic import BaseModel

from agents.schemas import ProposedAction
import config as cfg

class BehaviourResult(BaseModel):
    stage: str = "behaviour"
    flagged: bool
    score: float       # 0.0 to 1.0 based on severity/count of flags
    deviation_reason: Optional[str] = None


# State dictionary holding typical recent behaviour
# Format: { "agent_name": [action1, action2, ... ] }
_recent_history = {}


def reset_behaviour_history():
    """Clear memory (useful for testing eval grids)"""
    global _recent_history
    _recent_history = {}


from database.sqlite import query_recent_agent_messages
import json

def _load_history_from_db(agent: str):
    """Loads the last N actions for this agent from SQLite into memory."""
    if agent in _recent_history:
        return
        
    _recent_history[agent] = []
    
    # Query the last 50 messages to find up to BEHAVIOUR_HISTORY_SIZE for this agent
    try:
        messages = query_recent_agent_messages(50)
        for msg in messages:
            if msg["sender_agent"] == agent:
                try:
                    action_data = json.loads(msg["message_content"])
                    action = ProposedAction(**action_data)
                    _recent_history[agent].append(action)
                except Exception:
                    pass
    except Exception:
        pass
        
    # Keep only the most recent N
    _recent_history[agent] = _recent_history[agent][-cfg.BEHAVIOUR_HISTORY_SIZE:]


def analyze_behaviour(action: ProposedAction) -> BehaviourResult:
    """
    Analyzes action against recent history and produces an anomaly score.
    Checks for:
    - Unseen action types
    - Sudden priority jumps
    - Frequency anomalies (too many HIGH actions)
    - Target concentration (spamming same target)
    """
    agent = action.sender_agent
    
    # Pre-load from DB if not already loaded
    _load_history_from_db(agent)
        
    history = _recent_history[agent]
    
    # 1. New Agent (no baseline yet)
    if not history:
        _recent_history[agent].append(action)
        return BehaviourResult(
            flagged=False,
            score=0.0,
            deviation_reason="No baseline history yet; passing by default."
        )

    past_types = set([a.action_type for a in history])
    past_priorities = set([a.priority for a in history])
    
    reasons = []
    score = 0.0

    # Check 1: Unseen action type
    if action.action_type not in past_types:
        reasons.append(f"Action '{action.action_type}' never seen in recent history.")
        score += 0.3
        
    # Check 2: Severe escalation
    if action.priority == "HIGH" and "HIGH" not in past_priorities and "MEDIUM" not in past_priorities:
        reasons.append("Sudden escalation to HIGH priority without prior MEDIUM warnings.")
        score += 0.4
        
    # Check 3: Frequency anomaly
    if action.priority == "HIGH":
        high_count = sum(1 for a in history if a.priority == "HIGH")
        if high_count >= 3:
            reasons.append(f"Frequency anomaly: {high_count} HIGH priority actions in recent window.")
            score += 0.5
            
    # Check 4: Target concentration spam
    target_count = sum(1 for a in history if a.target == action.target and action.target not in ("none", "unknown"))
    if target_count >= 4:
         reasons.append(f"Target concentration: Component {action.target} targeted {target_count} times recently.")
         score += 0.3
         
    # Check 5: Flip-flop (alternating priorities wildly)
    if len(history) >= 2:
        last_pri = history[-1].priority
        prev_pri = history[-2].priority
        if (last_pri == "LOW" and action.priority == "HIGH") or (last_pri == "HIGH" and action.priority == "LOW"):
            if prev_pri == action.priority:
                reasons.append("Flip-flop behaviour detected in priority levels.")
                score += 0.2

    # Update memory
    _recent_history[agent].append(action)
    if len(_recent_history[agent]) > cfg.BEHAVIOUR_HISTORY_SIZE:
        _recent_history[agent].pop(0)
        
    score = min(1.0, score)
    flagged = score > 0.0
        
    return BehaviourResult(
        flagged=flagged,
        score=score,
        deviation_reason=" | ".join(reasons) if flagged else None
    )

if __name__ == "__main__":
    act1 = ProposedAction(action_id="1", action_type="MAINTAIN_STATUS", target="none", reason="test", priority="LOW")
    act2 = ProposedAction(action_id="2", action_type="ISOLATE_BATTERY", target="battery1", reason="test", priority="HIGH")
    
    print("Action 1:", analyze_behaviour(act1))
    print("Action 2:", analyze_behaviour(act2))
