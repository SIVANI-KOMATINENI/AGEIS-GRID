"""
attacks/replay.py
Simulates a replay attack using an old observation timestamp.
"""
from typing import Dict, Any

def apply_replay(observation: Dict[str, Any]) -> Dict[str, Any]:
    """
    Substitutes the current healthy state with an old, severe state
    that actually happened hours ago, trying to trigger a response 
    out of context.
    
    In a real implementation, this would query SQLite for an old severe row.
    For MVP testing, we hard-code the timestamp mismatch.
    """
    obs = dict(observation)
    
    # We pretend this is an old emergency from 04:00 AM
    obs["timestamp"] = "04:00"
    obs["battery_temperature_c"] = 85.0
    
    return obs
