"""
microgrid_test.py - Milestone 1 verification script.

Run this FIRST to confirm the microgrid network is working before adding any agents.
Expected output: a printed observation dict with sensible values.

Usage:
    python microgrid_test.py
"""

import sys
from pathlib import Path

# Ensure project root is on path
_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))

import pandapower as pp
from microgrid.network import create_microgrid
from microgrid.profiles import get_profiles_at_minute
from microgrid.observations import extract_observation


def test_network_creation():
    print("=" * 60)
    print("AEGIS Grid - Milestone 1: Microgrid Network Test")
    print("=" * 60)

    # 1. Build network
    net = create_microgrid()
    print("\n[OK] Network created: " + net.name)
    print("  Buses: %d, Lines: %d, Transformers: %d" % (
        len(net.bus), len(net.line), len(net.trafo)))
    print("  Loads: %d, Solar (sgen): %d, Battery (storage): %d" % (
        len(net.load), len(net.sgen), len(net.storage)))

    # 2. Test profiles at key time points
    print("\nProfile samples:")
    for minute in [0, 360, 720, 900, 1200, 1350]:
        p = get_profiles_at_minute(minute)
        hh, mm = divmod(minute, 60)
        print("  %02d:%02d -> solar=%.1f kW | load=%.1f kW | SoC=%.1f%% | temp=%.1f C" % (
            hh, mm,
            p["solar_kw"], p["load_kw"],
            p["battery_soc_pct"], p["battery_temp_c"]
        ))

    # 3. Run power flow and extract observation at noon
    print("\nRunning power flow at midday (minute 720)...")
    from microgrid.simulation import _apply_profiles_to_network
    profiles = get_profiles_at_minute(720)
    _apply_profiles_to_network(net, profiles)
    pp.runpp(net, numba=False)

    obs = extract_observation(net, timestamp="12:00", profiles=profiles)
    print("\nObservation at 12:00 (noon):")
    for k, v in obs.items():
        print("  %-30s = %s" % (k, v))

    # 4. Basic sanity checks
    assert 0.90 <= obs["voltage_pu"] <= 1.10, \
        "Voltage out of normal range: %.4f" % obs["voltage_pu"]
    assert obs["solar_kw"] >= 0, "Solar should be non-negative"
    assert obs["load_kw"] >= 0, "Load should be non-negative"
    assert 0 <= obs["battery_soc_pct"] <= 100, "SoC out of range"
    assert 15 <= obs["battery_temperature_c"] <= 65, \
        "Temp out of expected range: %.1f" % obs["battery_temperature_c"]

    print("\n[OK] All sanity checks passed!")

    # 5. Test nighttime (low solar)
    print("\nRunning power flow at midnight (minute 0)...")
    profiles_night = get_profiles_at_minute(0)
    _apply_profiles_to_network(net, profiles_night)
    pp.runpp(net, numba=False)
    obs_night = extract_observation(net, timestamp="00:00", profiles=profiles_night)
    print("  voltage_pu=%.4f, solar_kw=%.1f (should be ~0)" % (
        obs_night["voltage_pu"], obs_night["solar_kw"]))

    assert obs_night["solar_kw"] < 1.0, "Solar should be near-zero at midnight"
    print("\n[OK] Night-time profile check passed!")

    print("\n" + "=" * 60)
    print("Milestone 1 COMPLETE - microgrid network is working correctly.")
    print("Next step: run python microgrid/simulation.py to generate 24-hr CSV.")
    print("=" * 60)


if __name__ == "__main__":
    test_network_creation()
