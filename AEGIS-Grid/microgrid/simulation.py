"""
microgrid/simulation.py
Runs the 24-hour microgrid simulation and saves observations to CSV.

Usage:
    python simulation.py              # Runs full 24-hr sim, saves CSV
    python simulation.py --minutes 60 # Quick 1-hour test run
"""

from __future__ import annotations
import argparse
import csv
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import pandapower as pp

# Add project root to path when running as script
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from microgrid.network import create_microgrid
from microgrid.profiles import get_profiles_at_minute
from microgrid.observations import extract_observation
import config as cfg


# CSV column order (matches SQLite schema in database/sqlite.py)
CSV_FIELDS = [
    "timestamp", "voltage_pu", "load_kw", "solar_kw",
    "battery_soc_pct", "battery_temperature_c", "transformer_loading_pct"
]

# Simulation start date (arbitrary - only time matters for profiling)
SIM_DATE = datetime(2024, 1, 1, 0, 0, 0)


def _apply_profiles_to_network(net: pp.pandapowerNet, profiles: dict) -> None:
    """Update network element setpoints from the current timestep's profiles."""
    idx = net._aegis

    # Scale solar generation
    net.sgen.at[idx["solar_idx"], "p_mw"] = profiles["solar_kw"] / 1000.0

    # Scale total load proportionally across the two loads
    total_load_mw = profiles["load_kw"] / 1000.0
    net.load.at[idx["load1_idx"], "p_mw"] = total_load_mw * 0.43      # 30/70
    net.load.at[idx["critical_load_idx"], "p_mw"] = total_load_mw * 0.57  # 40/70

    # Battery: charging when SoC rising, discharging otherwise (approx)
    soc = profiles["battery_soc_pct"]
    bat_p = 0.01 if soc < 60 else -0.01
    net.storage.at[idx["battery_idx"], "p_mw"] = bat_p
    net.storage.at[idx["battery_idx"], "soc_percent"] = soc


def run_simulation(duration_minutes=None, output_csv=None, verbose=False):
    """
    Run the microgrid simulation for `duration_minutes` timesteps (1 min each).

    Args:
        duration_minutes: Total minutes to simulate. Defaults to cfg.SIM_DURATION_HOURS * 60.
        output_csv:       Path to save the observations CSV.
        verbose:          Print progress every 60 steps.

    Returns:
        List of observation dicts.
    """
    total_minutes = duration_minutes or (cfg.SIM_DURATION_HOURS * 60)
    csv_path = output_csv or cfg.MICROGRID_CSV

    # Ensure output directory exists
    Path(csv_path).parent.mkdir(parents=True, exist_ok=True)

    net = create_microgrid()
    observations = []

    start = time.time()
    print("Starting %d-minute simulation -> %s" % (total_minutes, csv_path))

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()

        for minute in range(total_minutes):
            ts = (SIM_DATE + timedelta(minutes=minute)).strftime("%H:%M")

            # Load profile for this minute
            profiles = get_profiles_at_minute(minute)

            # Update network setpoints
            _apply_profiles_to_network(net, profiles)

            # Run power flow
            try:
                pp.runpp(net, numba=False, verbose=False)
            except Exception:
                # Fallback: reuse last observation if power flow fails
                if observations:
                    obs = dict(observations[-1])
                    obs["timestamp"] = ts
                    observations.append(obs)
                    writer.writerow(obs)
                continue

            obs = extract_observation(net, timestamp=ts, profiles=profiles)
            observations.append(obs)
            writer.writerow(obs)

            if verbose and minute % 60 == 0:
                elapsed = time.time() - start
                hh, mm = divmod(minute, 60)
                print("  [%02d:%02d] V=%.4f pu | Solar=%.1f kW | Load=%.1f kW | "
                      "SoC=%.0f%% | Temp=%.1f C | Trafo=%.1f%% (%.1fs elapsed)" % (
                      hh, mm, obs["voltage_pu"], obs["solar_kw"], obs["load_kw"],
                      obs["battery_soc_pct"], obs["battery_temperature_c"],
                      obs["transformer_loading_pct"], elapsed))

    elapsed = time.time() - start
    print("\nSimulation complete: %d steps in %.1fs" % (total_minutes, elapsed))
    print("Saved %d observations -> %s" % (len(observations), csv_path))
    return observations


def get_observation_at_minute(minute, observations=None):
    """
    Return the observation dict for a specific simulation minute.
    If observations list not passed, loads from CSV.
    """
    import csv as _csv
    if observations is not None:
        return observations[minute % len(observations)]

    csv_path = cfg.MICROGRID_CSV
    if not Path(csv_path).exists():
        raise FileNotFoundError(
            "Observations CSV not found: %s\n"
            "Run: python microgrid/simulation.py first." % csv_path
        )
    with open(csv_path, encoding="utf-8") as f:
        rows = list(_csv.DictReader(f))
    if not rows:
        raise ValueError("Observations CSV is empty.")
    row = rows[minute % len(rows)]
    return {
        "timestamp":               row["timestamp"],
        "voltage_pu":              float(row["voltage_pu"]),
        "load_kw":                 float(row["load_kw"]),
        "solar_kw":                float(row["solar_kw"]),
        "battery_soc_pct":         float(row["battery_soc_pct"]),
        "battery_temperature_c":   float(row["battery_temperature_c"]),
        "transformer_loading_pct": float(row["transformer_loading_pct"]),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run AEGIS Grid microgrid simulation")
    parser.add_argument("--minutes", type=int, default=None,
                        help="Number of minutes to simulate (default: 1440 = 24 hrs)")
    parser.add_argument("--output", type=str, default=None,
                        help="Output CSV path")
    parser.add_argument("--verbose", action="store_true",
                        help="Print hourly progress")
    args = parser.parse_args()

    run_simulation(
        duration_minutes=args.minutes,
        output_csv=args.output,
        verbose=True
    )
