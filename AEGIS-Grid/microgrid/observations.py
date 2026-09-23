"""
microgrid/observations.py
Extracts the standard 7-field observation dict from a pandapower network result.

Standard observation schema (used everywhere in AEGIS Grid):
{
    "timestamp":             str   (ISO-8601 or HH:MM),
    "voltage_pu":            float (bus 1 voltage, per-unit),
    "load_kw":               float (total active load, kW),
    "solar_kw":              float (solar generation, kW),
    "battery_soc_pct":       float (state of charge, %),
    "battery_temperature_c": float (battery temperature, °C),
    "transformer_loading_pct": float (transformer loading, %)
}
"""

from __future__ import annotations
import pandapower as pp


def extract_observation(net: pp.pandapowerNet, timestamp: str,
                        profiles: dict | None = None) -> dict:
    """
    Extract the standard 7-field observation from a solved pandapower network.

    Args:
        net:       A solved pandapower network (pp.runpp already called).
        timestamp: Simulation timestamp string (e.g. "00:00", "2024-01-01T00:00").
        profiles:  Optional profile dict from profiles.get_profiles_at_minute(),
                   used to fill battery_soc_pct and battery_temperature_c
                   (these are not available directly from power-flow results).

    Returns:
        dict with the 7 standard fields.
    """
    idx = net._aegis

    # Bus 1 (LV hub) voltage in per-unit
    voltage_pu = float(net.res_bus.at[idx["bus1"], "vm_pu"])

    # Total load (MW × 1000 = kW)
    load_kw = float(
        net.res_load["p_mw"].sum() * 1000.0
    )

    # Solar generation
    solar_kw = float(
        net.res_sgen.at[idx["solar_idx"], "p_mw"] * 1000.0
        if not net.res_sgen.empty else 0.0
    )

    # Transformer loading
    trafo_loading = float(
        net.res_trafo["loading_percent"].iloc[0]
        if not net.res_trafo.empty else 0.0
    )

    # Battery SoC and temperature come from profiles (not direct power-flow output)
    battery_soc = float(profiles.get("battery_soc_pct", 50.0)) if profiles else 50.0
    battery_temp = float(profiles.get("battery_temp_c", 30.0)) if profiles else 30.0

    return {
        "timestamp":               timestamp,
        "voltage_pu":              round(voltage_pu, 4),
        "load_kw":                 round(load_kw, 2),
        "solar_kw":                round(solar_kw, 2),
        "battery_soc_pct":         round(battery_soc, 1),
        "battery_temperature_c":   round(battery_temp, 1),
        "transformer_loading_pct": round(trafo_loading, 2),
    }
 