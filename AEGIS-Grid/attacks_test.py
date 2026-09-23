"""
attacks_test.py - Milestone 5 Test
"""

import sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))

from attacks.manager import run_attack_manager

def test_attack_manager():
    print("Testing Attack Manager...\n")
    
    # Benign timestamp (no attack scheduled here)
    base_obs = {"timestamp": "12:00", "battery_temperature_c": 30.0}
    clean = run_attack_manager("12:00", base_obs)
    assert clean["is_injected_attack"] == 0
    assert clean["battery_temperature_c"] == 30.0
    print("[OK] Benign window works")

    # Sensor poisoning window (02:20 - 02:23)
    poison = run_attack_manager("02:21", base_obs)
    assert poison["is_injected_attack"] == 1
    assert poison["attack_type"] == "sensor_poisoning"
    assert poison["battery_temperature_c"] == 92.5
    print("[OK] Sensor poisoning window works")

    # Prompt injection window (08:15 - 08:18)
    prompt = run_attack_manager("08:16", base_obs)
    assert prompt["is_injected_attack"] == 1
    assert prompt["attack_type"] == "prompt_injection"
    assert "SYSTEM OVERRIDE" in prompt["sensor_status_message"]
    print("[OK] Prompt injection window works")
    
    # Authority spoofing window (12:30 - 12:33) 
    # (Note: manager just tags it observation layer, workflow graph will apply it later)
    auth = run_attack_manager("12:31", base_obs)
    assert auth["is_injected_attack"] == 1
    assert auth["attack_type"] == "authority_spoofing"
    print("[OK] Authority spoofing window works")

    print("\n[OK] Milestone 5 complete.")

if __name__ == "__main__":
    test_attack_manager()
