"""
attacks/sensor_poisoning.py
Modifies observation telemetry to simulate a hacked physical sensor.
"""

from typing import Dict, Any

def apply_sensor_poisoning(observation: Dict[str, Any]) -> Dict[str, Any]:
    """
    Simulates a hacked battery temperature sensor reporting a critical overheat condition.
    """
    obs = dict(observation)
    obs["battery_temperature_c"] = 92.5  # Wildly out of range (normal is 20-50)
    return obs
