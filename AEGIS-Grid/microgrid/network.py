"""
microgrid/network.py
Custom 6-bus pandapower microgrid network.

Topology:
    External Grid
         |
     Transformer (HV→LV)
         |
       Bus 1  (LV slack / distribution hub)
      /     \\
  Bus 2     Bus 3
  (Solar)   (Battery)
     |
   Bus 4
  /      \\
Bus 5   Bus 6
(Load 1) (Critical Load)
"""

import pandapower as pp
import pandapower.networks as pn
import numpy as np


def create_microgrid() -> pp.pandapowerNet:
    """
    Build and return the custom 6-bus microgrid network.
    Component indices are stored in net._aegis for easy reference elsewhere.
    """
    net = pp.create_empty_network(name="AEGIS-Microgrid", f_hz=50.0, sn_mva=1.0)

    # ── Buses ─────────────────────────────────────────────────────────────────
    hv_bus = pp.create_bus(net, vn_kv=11.0,  name="HV_Bus")          # 0 – HV side
    bus1   = pp.create_bus(net, vn_kv=0.415, name="Bus1_Hub")         # 1 – LV hub
    bus2   = pp.create_bus(net, vn_kv=0.415, name="Bus2_Solar")       # 2 – solar
    bus3   = pp.create_bus(net, vn_kv=0.415, name="Bus3_Battery")     # 3 – battery
    bus4   = pp.create_bus(net, vn_kv=0.415, name="Bus4_LoadHub")     # 4 – load hub
    bus5   = pp.create_bus(net, vn_kv=0.415, name="Bus5_Load1")       # 5 – load 1
    bus6   = pp.create_bus(net, vn_kv=0.415, name="Bus6_Critical")    # 6 – critical load

    # ── External grid connection ───────────────────────────────────────────────
    ext = pp.create_ext_grid(net, bus=hv_bus, vm_pu=1.02, name="ExternalGrid")

    # ── Transformer (11 kV → 415 V) ───────────────────────────────────────────
    # Use a standard type; adjust if pandapower version differs
    trafo = pp.create_transformer_from_parameters(
        net,
        hv_bus=hv_bus, lv_bus=bus1,
        sn_mva=0.25,
        vn_hv_kv=11.0, vn_lv_kv=0.415,
        vkr_percent=1.5, vk_percent=6.0,
        pfe_kw=0.5, i0_percent=0.4,
        name="Transformer_HV_LV"
    )

    # ── Lines (LV, low-impedance distribution cables) ─────────────────────────
    # Bus1 → Bus2 (solar feeder)
    l1 = pp.create_line_from_parameters(
        net, from_bus=bus1, to_bus=bus2, length_km=0.05,
        r_ohm_per_km=0.64, x_ohm_per_km=0.083,
        c_nf_per_km=210, max_i_ka=0.142, name="Line_1_2"
    )
    # Bus1 → Bus3 (battery feeder)
    l2 = pp.create_line_from_parameters(
        net, from_bus=bus1, to_bus=bus3, length_km=0.05,
        r_ohm_per_km=0.64, x_ohm_per_km=0.083,
        c_nf_per_km=210, max_i_ka=0.142, name="Line_1_3"
    )
    # Bus2 → Bus4 (load hub)
    l3 = pp.create_line_from_parameters(
        net, from_bus=bus2, to_bus=bus4, length_km=0.08,
        r_ohm_per_km=0.64, x_ohm_per_km=0.083,
        c_nf_per_km=210, max_i_ka=0.142, name="Line_2_4"
    )
    # Bus4 → Bus5
    l4 = pp.create_line_from_parameters(
        net, from_bus=bus4, to_bus=bus5, length_km=0.04,
        r_ohm_per_km=1.15, x_ohm_per_km=0.083,
        c_nf_per_km=210, max_i_ka=0.108, name="Line_4_5"
    )
    # Bus4 → Bus6
    l5 = pp.create_line_from_parameters(
        net, from_bus=bus4, to_bus=bus6, length_km=0.04,
        r_ohm_per_km=1.15, x_ohm_per_km=0.083,
        c_nf_per_km=210, max_i_ka=0.108, name="Line_4_6"
    )

    # ── Solar generator (PV, bus 2) ────────────────────────────────────────────
    solar = pp.create_sgen(
        net, bus=bus2, p_mw=0.05, q_mvar=0.0,
        name="Solar_PV", type="PV"
    )

    # ── Battery storage (bus 3) ────────────────────────────────────────────────
    battery = pp.create_storage(
        net, bus=bus3, p_mw=0.02, max_e_mwh=0.1,
        soc_percent=50.0, q_mvar=0.0, name="Battery_1"
    )

    # ── Loads ──────────────────────────────────────────────────────────────────
    load1 = pp.create_load(
        net, bus=bus5, p_mw=0.03, q_mvar=0.01,
        name="Load_1"
    )
    crit_load = pp.create_load(
        net, bus=bus6, p_mw=0.04, q_mvar=0.01,
        name="Critical_Load", controllable=False
    )

    # ── Store component indices for easy lookup ───────────────────────────────
    net._aegis = {
        "hv_bus": hv_bus,
        "bus1": bus1, "bus2_solar": bus2, "bus3_battery": bus3,
        "bus4_loadhub": bus4, "bus5_load1": bus5, "bus6_critical": bus6,
        "solar_idx": solar,
        "battery_idx": battery,
        "load1_idx": load1,
        "critical_load_idx": crit_load,
    }

    return net


if __name__ == "__main__":
    net = create_microgrid()
    pp.runpp(net, numba=False)
    print("Network created successfully.")
    print(net)
    print("\nBus voltages (p.u.):")
    print(net.res_bus[["vm_pu", "va_degree"]])
    print("\nLine loading (%):")
    print(net.res_line[["loading_percent"]])
    print("\nTransformer loading (%):")
    print(net.res_trafo[["loading_percent"]])
