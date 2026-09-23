"""
microgrid/profiles.py
24-hour time-series profiles for load, solar, and battery.

All profiles are numpy arrays of length 1440 (one value per minute over 24 hours).
Values are in per-unit relative to the rated capacity defined in network.py.
"""

import numpy as np

# Total minutes in simulation
MINUTES_PER_DAY = 1440
_t = np.linspace(0, 24, MINUTES_PER_DAY, endpoint=False)  # hours 0..24


def _solar_irradiance(t: np.ndarray) -> np.ndarray:
    """
    Sinusoidal solar profile: peaks at noon (12:00), zero outside 6:00–18:00.
    Returns per-unit values 0.0 – 1.0.
    """
    profile = np.zeros_like(t)
    mask = (t >= 6.0) & (t <= 18.0)
    profile[mask] = np.sin(np.pi * (t[mask] - 6.0) / 12.0)
    # Add small random cloud cover variation (±5 %)
    rng = np.random.default_rng(seed=42)
    noise = rng.uniform(-0.05, 0.05, size=t.shape)
    profile = np.clip(profile + noise * mask, 0.0, 1.0)
    return profile


def _load_demand(t: np.ndarray) -> np.ndarray:
    """
    Realistic residential/commercial load profile:
    Low at night, morning peak ~08:00, evening peak ~19:00.
    Returns per-unit values 0.3 – 1.0.
    """
    # Base sinusoidal with two humps
    base = 0.3 + 0.35 * (
        0.5 * np.exp(-((t - 8.0) ** 2) / 2.0)      # morning peak
        + 0.8 * np.exp(-((t - 19.0) ** 2) / 2.0)   # evening peak
        + 0.2 * np.exp(-((t - 13.0) ** 2) / 4.0)   # lunch dip
    )
    rng = np.random.default_rng(seed=7)
    noise = rng.uniform(-0.03, 0.03, size=t.shape)
    return np.clip(base + noise, 0.2, 1.05)


def _battery_soc(t: np.ndarray) -> np.ndarray:
    """
    Simple battery SoC profile:
    Charges during solar hours (6–15), discharges in evening (15–22).
    Returns percent values 20–90 %.
    """
    soc = np.zeros_like(t)
    soc[0] = 50.0
    for i in range(1, len(t)):
        hour = t[i]
        if 6.0 <= hour <= 15.0:
            soc[i] = min(soc[i - 1] + 0.04, 90.0)   # charging
        elif 15.0 < hour <= 22.0:
            soc[i] = max(soc[i - 1] - 0.05, 20.0)   # discharging
        else:
            soc[i] = soc[i - 1]                       # idle
    return soc


def _battery_temperature(t: np.ndarray, soc: np.ndarray) -> np.ndarray:
    """
    Battery temperature profile:
    Correlates with charge/discharge activity.
    Normal operating range: 20–50 °C.
    """
    base_temp = 25.0
    activity = np.abs(np.gradient(soc))
    temp = base_temp + 15.0 * activity / (activity.max() + 1e-9)
    rng = np.random.default_rng(seed=11)
    noise = rng.uniform(-1.0, 1.0, size=t.shape)
    return np.clip(temp + noise, 20.0, 48.0)


# ── Pre-computed profiles (cached at import time) ──────────────────────────────
SOLAR_PU    = _solar_irradiance(_t)
LOAD_PU     = _load_demand(_t)
BATTERY_SOC = _battery_soc(_t)
BATTERY_TEMP = _battery_temperature(_t, BATTERY_SOC)

# Rated capacities (MW) matching network.py
SOLAR_RATED_MW   = 0.05   # 50 kW solar PV
LOAD_RATED_MW    = 0.07   # 70 kW total load (30 kW + 40 kW)
BATTERY_RATED_MW = 0.02   # 20 kW battery


def get_profiles_at_minute(minute: int) -> dict:
    """Return profile values at a given simulation minute (0–1439)."""
    idx = minute % MINUTES_PER_DAY
    return {
        "solar_pu":         float(SOLAR_PU[idx]),
        "load_pu":          float(LOAD_PU[idx]),
        "battery_soc_pct":  float(BATTERY_SOC[idx]),
        "battery_temp_c":   float(BATTERY_TEMP[idx]),
        "solar_kw":         float(SOLAR_PU[idx] * SOLAR_RATED_MW * 1000),
        "load_kw":          float(LOAD_PU[idx] * LOAD_RATED_MW * 1000),
    }


if __name__ == "__main__":
    import sys
    print("Sample profiles:")
    for m in [0, 360, 720, 1080, 1439]:
        p = get_profiles_at_minute(m)
        hh, mm = divmod(m, 60)
        print(f"  {hh:02d}:{mm:02d} → solar={p['solar_kw']:.1f} kW, "
              f"load={p['load_kw']:.1f} kW, SoC={p['battery_soc_pct']:.1f}%, "
              f"temp={p['battery_temp_c']:.1f}°C")
