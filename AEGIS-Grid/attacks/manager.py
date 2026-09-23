"""
attacks/manager.py
The Attack Scenario Manager.
Responsible for checking the current timestep against the attack schedule
and invoking the appropriate attack module.
"""

from typing import Dict, Any

from attacks.sensor_poisoning import apply_sensor_poisoning
from attacks.prompt_injection import apply_prompt_injection
from attacks.authority_spoofing import apply_authority_spoofing
from attacks.cross_agent import apply_cross_agent
from attacks.replay import apply_replay


# Defined controlled windows for testing each attack type in the 24hr cycle.
# Using HH:MM strings to match the simulation timestamps.
ATTACK_SCHEDULE = [
    {"start": "02:20", "end": "02:23", "type": "sensor_poisoning"},
    {"start": "08:15", "end": "08:18", "type": "prompt_injection"},
    {"start": "12:30", "end": "12:33", "type": "authority_spoofing"},
    {"start": "16:45", "end": "16:48", "type": "cross_agent"},
    {"start": "20:10", "end": "20:13", "type": "replay"}
]


def check_for_active_attack(timestamp_hhmm: str) -> str | None:
    """
    Checks if the current timestamp falls within any scheduled attack window.
    Returns the attack type string, or None.
    """
    for window in ATTACK_SCHEDULE:
        if window["start"] <= timestamp_hhmm <= window["end"]:
            return window["type"]
    return None


def run_attack_manager(
    timestamp: str,
    original_observation: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Intercepts the physical observation from the microgrid before it hits the agents.
    If an attack is active, it modifies the data based on the attack type.
    Crucially, it attaches ground_truth fields.
    """
    attack_type = check_for_active_attack(timestamp)
    
    # Create a copy so we don't mutate the raw simulation object
    obs_copy = dict(original_observation)
    
    if not attack_type:
        obs_copy["is_injected_attack"] = 0
        obs_copy["attack_type"] = None
        return obs_copy

    obs_copy["is_injected_attack"] = 1
    obs_copy["attack_type"] = attack_type

    # Apply the specific attack logic at the observation stage
    if attack_type == "sensor_poisoning":
        obs_copy = apply_sensor_poisoning(obs_copy)
    elif attack_type == "prompt_injection":
        obs_copy = apply_prompt_injection(obs_copy)
    elif attack_type == "replay":
        obs_copy = apply_replay(obs_copy)
        
    return obs_copy

