# from datetime import datetime
# from pathlib import Path
# import sys
# from database.sqlite import init_db

# import pandapower as pp

# # Add project root to Python path
# ROOT = Path(__file__).resolve().parent
# sys.path.insert(0, str(ROOT))

# from microgrid.network import create_microgrid
# from microgrid.profiles import get_profiles_at_minute
# from microgrid.observations import extract_observation
# from workflow.graph import build_workflow


# def create_current_observation():
#     """
#     Create a microgrid observation using the current real-world time.
#     The current time determines which minute of the simulated daily
#     profile is used.
#     """

#     # Actual computer time
#     now = datetime.now()

#     # Minute of the current day
#     minute_of_day = now.hour * 60 + now.minute

#     # Create the pandapower network
#     net = create_microgrid()

#     # Get the grid profile for the current simulated minute
#     profiles = get_profiles_at_minute(minute_of_day)

#     # Apply profile values to the network
#     idx = net._aegis

#     net.sgen.at[idx["solar_idx"], "p_mw"] = (
#         profiles["solar_kw"] / 1000.0
#     )

#     total_load_mw = profiles["load_kw"] / 1000.0

#     net.load.at[idx["load1_idx"], "p_mw"] = total_load_mw * 0.43
#     net.load.at[idx["critical_load_idx"], "p_mw"] = total_load_mw * 0.57

#     # Battery
#     soc = profiles["battery_soc_pct"]

#     if soc < 60:
#         battery_power = 0.01
#     else:
#         battery_power = -0.01

#     net.storage.at[idx["battery_idx"], "p_mw"] = battery_power
#     net.storage.at[idx["battery_idx"], "soc_percent"] = soc

#     # Run power flow
#     pp.runpp(net, numba=False, verbose=False)

#     # Extract observation
#     simulation_timestamp = now.strftime("%H:%M")

#     observation = extract_observation(
#         net,
#         timestamp=simulation_timestamp,
#         profiles=profiles
#     )

#     return observation, now, minute_of_day


# def main():

#     print("=" * 60)
#     print("        AEGIS GRID - END-TO-END DEMONSTRATION")
#     print("=" * 60)

#     print("\n[0] INITIALIZING DATABASE")
#     init_db()
#     print("    [OK] SQLite database ready")

#     # ---------------------------------------------------------
#     # 1. Generate current microgrid observation
#     # ---------------------------------------------------------

#     observation, real_time, minute = create_current_observation()

#     print("\n[1] CURRENT EXECUTION TIME")
#     print("    ", real_time.strftime("%Y-%m-%d %H:%M:%S"))

#     print("\n[2] MICROGRID OBSERVATION")
#     print("    Simulation time       :", observation["timestamp"])
#     print("    Simulation minute     :", minute)
#     print("    Voltage               :", observation["voltage_pu"], "pu")
#     print("    Load                  :", observation["load_kw"], "kW")
#     print("    Solar                 :", observation["solar_kw"], "kW")
#     print("    Battery SoC           :", observation["battery_soc_pct"], "%")
#     print(
#         "    Battery Temperature   :",
#         observation["battery_temperature_c"],
#         "C"
#     )
#     print(
#         "    Transformer Loading   :",
#         observation["transformer_loading_pct"],
#         "%"
#     )

#     # ---------------------------------------------------------
#     # 2. Build LangGraph workflow
#     # ---------------------------------------------------------

#     print("\n[3] BUILDING AEGIS WORKFLOW")

#     workflow = build_workflow()

#     print("    [OK] Workflow created")

#     # ---------------------------------------------------------
#     # 3. Initial state
#     # ---------------------------------------------------------

#     initial_state = {
#         "raw_observation": observation,
#         "active_attack_type": None,
#         "is_injected_attack": 0,
#         "observation": {},
#         "monitoring_input": {},
#         "diagnostic_report": {},
#         "response_input": {},
#         "proposed_action": {},
#         "policy_res": {},
#         "prov_res": {},
#         "behav_res": {},
#         "risk_res": {},
#         "final_decision": {}
#     }

#     # ---------------------------------------------------------
#     # 4. Run complete workflow
#     # ---------------------------------------------------------

#     print("\n[4] RUNNING AEGIS PIPELINE")
#     print("    Microgrid")
#     print("       ↓")
#     print("    Monitoring Agent")
#     print("       ↓")
#     print("    Response Agent")
#     print("       ↓")
#     print("    Policy")
#     print("       ↓")
#     print("    Provenance")
#     print("       ↓")
#     print("    Behaviour")
#     print("       ↓")
#     print("    Risk")
#     print("       ↓")
#     print("    Decision")

#     final_state = workflow.invoke(initial_state)

#     # ---------------------------------------------------------
#     # 5. Display Monitoring Agent result
#     # ---------------------------------------------------------

#     report = final_state["diagnostic_report"]

#     print("\n" + "=" * 60)
#     print("MONITORING AGENT RESULT")
#     print("=" * 60)

#     print("Status       :", report.get("status"))
#     print("Severity     :", report.get("severity"))
#     print("Issue        :", report.get("issue"))
#     print("Confidence   :", report.get("confidence"))

#     # ---------------------------------------------------------
#     # 6. Display Response Agent result
#     # ---------------------------------------------------------

#     action = final_state["proposed_action"]

#     print("\n" + "=" * 60)
#     print("RESPONSE AGENT - PROPOSED ACTION")
#     print("=" * 60)

#     print("Action ID          :", action.get("action_id"))
#     print("Sender Agent       :", action.get("sender_agent"))
#     print("Action Type        :", action.get("action_type"))
#     print("Target             :", action.get("target"))
#     print("Priority           :", action.get("priority"))
#     print("Reason             :", action.get("reason"))
#     print("Claimed Authority  :", action.get("claimed_authorization"))

#     # ---------------------------------------------------------
#     # 7. Display AEGIS results
#     # ---------------------------------------------------------

#     policy = final_state["policy_res"]
#     provenance = final_state["prov_res"]
#     behaviour = final_state["behav_res"]
#     risk = final_state["risk_res"]
#     decision = final_state["final_decision"]

#     print("\n" + "=" * 60)
#     print("AEGIS SECURITY ANALYSIS")
#     print("=" * 60)

#     print("\nPOLICY")
#     print("    Allowed :", policy.get("allowed"))
#     print("    Reason  :", policy.get("reason"))

#     print("\nPROVENANCE")
#     print("    Verified :", provenance.get("verified"))
#     print("    Reason   :", provenance.get("reason"))

#     print("\nBEHAVIOUR")
#     print("    Flagged :", behaviour.get("flagged"))
#     print("    Reason  :", behaviour.get("reason"))

#     print("\nRISK")
#     print("    Score :", risk.get("score"))
#     print("    Level :", risk.get("level"))

#     print("\nFINAL DECISION")
#     print("    >>>", decision.get("final_decision", "").upper())
#     print("    Reason:", decision.get("reason"))

#     print("\n" + "=" * 60)
#     print("        END-TO-END DEMONSTRATION COMPLETE")
#     print("=" * 60)


# if __name__ == "__main__":
#     main()/




"""
main.py

AEGIS Grid end-to-end demonstration.

Usage:

    python main.py --scenario normal
    python main.py --scenario sensor_poisoning
    python main.py --scenario authority_spoofing
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

import pandapower as pp

# Add project root to Python path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from database.sqlite import init_db

from microgrid.network import create_microgrid
from microgrid.profiles import get_profiles_at_minute
from microgrid.observations import extract_observation

from workflow.graph import build_workflow


# ─────────────────────────────────────────────────────────────────────────────
# COMMAND-LINE SCENARIO
# ─────────────────────────────────────────────────────────────────────────────

def get_scenario():

    parser = argparse.ArgumentParser(
        description="AEGIS Grid end-to-end demonstration"
    )

    parser.add_argument(
        "--scenario",
        choices=[
            "normal",
            "sensor_poisoning",
            "authority_spoofing"
        ],
        default="normal",
        help="Scenario to demonstrate"
    )

    args = parser.parse_args()

    return args.scenario


# ─────────────────────────────────────────────────────────────────────────────
# CREATE CURRENT MICROGRID OBSERVATION
# ─────────────────────────────────────────────────────────────────────────────

def create_current_observation():

    """
    Creates one microgrid observation using the current computer time.

    The real clock determines which minute of the simulated daily
    profile is used.
    """

    # Actual computer time
    now = datetime.now()

    # Convert current time to minute of day
    minute_of_day = (
        now.hour * 60
        + now.minute
    )

    # Create pandapower network
    net = create_microgrid()

    # Get simulated profile
    profiles = get_profiles_at_minute(
        minute_of_day
    )

    # ---------------------------------------------------------
    # APPLY SOLAR
    # ---------------------------------------------------------

    idx = net._aegis

    net.sgen.at[
        idx["solar_idx"],
        "p_mw"
    ] = profiles["solar_kw"] / 1000.0

    # ---------------------------------------------------------
    # APPLY LOAD
    # ---------------------------------------------------------

    total_load_mw = (
        profiles["load_kw"] / 1000.0
    )

    net.load.at[
        idx["load1_idx"],
        "p_mw"
    ] = total_load_mw * 0.43

    net.load.at[
        idx["critical_load_idx"],
        "p_mw"
    ] = total_load_mw * 0.57

    # ---------------------------------------------------------
    # APPLY BATTERY
    # ---------------------------------------------------------

    soc = profiles["battery_soc_pct"]

    if soc < 60:
        battery_power = 0.01
    else:
        battery_power = -0.01

    net.storage.at[
        idx["battery_idx"],
        "p_mw"
    ] = battery_power

    net.storage.at[
        idx["battery_idx"],
        "soc_percent"
    ] = soc

    # ---------------------------------------------------------
    # RUN POWER FLOW
    # ---------------------------------------------------------

    pp.runpp(
        net,
        numba=False,
        verbose=False
    )

    # ---------------------------------------------------------
    # EXTRACT OBSERVATION
    # ---------------------------------------------------------

    simulation_timestamp = now.strftime(
        "%H:%M"
    )

    observation = extract_observation(
        net,
        timestamp=simulation_timestamp,
        profiles=profiles
    )

    return (
        observation,
        now,
        minute_of_day
    )


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():

    scenario = get_scenario()

    print("=" * 60)
    print("        AEGIS GRID - END-TO-END DEMONSTRATION")
    print("=" * 60)

    # ---------------------------------------------------------
    # 0. DATABASE
    # ---------------------------------------------------------

    print("\n[0] INITIALIZING DATABASE")

    init_db()

    print("    [OK] SQLite database ready")

    # ---------------------------------------------------------
    # 1. SCENARIO
    # ---------------------------------------------------------

    print("\n[1] SELECTED DEMONSTRATION SCENARIO")

    print(
        "    Scenario :",
        scenario.upper()
    )

    if scenario == "normal":

        print(
            "    Attack   : NONE"
        )

    elif scenario == "sensor_poisoning":

        print(
            "    Attack   : SENSOR POISONING"
        )

    elif scenario == "authority_spoofing":

        print(
            "    Attack   : AUTHORITY SPOOFING"
        )

    # ---------------------------------------------------------
    # 2. CURRENT MICROGRID OBSERVATION
    # ---------------------------------------------------------

    observation, real_time, minute = (
        create_current_observation()
    )

    print("\n[2] CURRENT EXECUTION TIME")

    print(
        "    ",
        real_time.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    print("\n[3] MICROGRID OBSERVATION")

    print(
        "    Simulation time       :",
        observation["timestamp"]
    )

    print(
        "    Simulation minute     :",
        minute
    )

    print(
        "    Voltage               :",
        observation["voltage_pu"],
        "pu"
    )

    print(
        "    Load                  :",
        observation["load_kw"],
        "kW"
    )

    print(
        "    Solar                 :",
        observation["solar_kw"],
        "kW"
    )

    print(
        "    Battery SoC           :",
        observation["battery_soc_pct"],
        "%"
    )

    print(
        "    Battery Temperature   :",
        observation["battery_temperature_c"],
        "C"
    )

    print(
        "    Transformer Loading   :",
        observation["transformer_loading_pct"],
        "%"
    )

    # ---------------------------------------------------------
    # 4. BUILD WORKFLOW
    # ---------------------------------------------------------

    print("\n[4] BUILDING AEGIS WORKFLOW")

    workflow = build_workflow()

    print(
        "    [OK] Workflow created"
    )

    # ---------------------------------------------------------
    # 5. INITIAL STATE
    # ---------------------------------------------------------

    initial_state = {
        "observation": observation,
        "demo_scenario": scenario
    }

    # ---------------------------------------------------------
    # 6. RUN PIPELINE
    # ---------------------------------------------------------

    print("\n[5] RUNNING AEGIS PIPELINE")

    print("    Microgrid")
    print("       ↓")
    print("    Attack Scenario")
    print("       ↓")
    print("    Monitoring Agent")
    print("       ↓")
    print("    Response Agent")
    print("       ↓")
    print("    Policy")
    print("       ↓")
    print("    Provenance")
    print("       ↓")
    print("    Behaviour")
    print("       ↓")
    print("    Risk")
    print("       ↓")
    print("    Decision")

    final_state = workflow.invoke(
        initial_state
    )

    result = final_state["workflow_result"]

    # ---------------------------------------------------------
    # 7. ATTACK STATUS
    # ---------------------------------------------------------

    print("\n" + "=" * 60)
    print("ATTACK STATUS")
    print("=" * 60)

    attack_context = final_state["attack_context"]
    active_attack = attack_context.attack_type
    injected = attack_context.is_injected_attack

    print(
        "Attack type :", 
        active_attack or "NONE"
    )

    print(
        "Injected    :",
        "YES" if injected else "NO"
    )

    # ---------------------------------------------------------
    # 8. MONITORING AGENT
    # ---------------------------------------------------------

    report = final_state["diagnostic_report"].model_dump()

    print("\n" + "=" * 60)
    print("MONITORING AGENT RESULT")
    print("=" * 60)

    print(
        "Status       :",
        report.get("status")
    )

    print(
        "Severity     :",
        report.get("severity")
    )

    print(
        "Issue        :",
        report.get("issue")
    )

    print(
        "Confidence   :",
        report.get("confidence")
    )

    # ---------------------------------------------------------
    # 9. RESPONSE AGENT
    # ---------------------------------------------------------

    action = result.proposed_action.model_dump()

    print("\n" + "=" * 60)
    print("RESPONSE AGENT - PROPOSED ACTION")
    print("=" * 60)

    print(
        "Action ID          :",
        action.get("action_id")
    )

    print(
        "Sender Agent       :",
        action.get("sender_agent")
    )

    print(
        "Action Type        :",
        action.get("action_type")
    )

    print(
        "Target             :",
        action.get("target")
    )

    print(
        "Priority           :",
        action.get("priority")
    )

    print(
        "Reason             :",
        action.get("reason")
    )

    print(
        "Claimed Authority  :",
        action.get("claimed_authorization")
    )

    # ---------------------------------------------------------
    # 10. AEGIS SECURITY RESULTS
    # ---------------------------------------------------------

    aegis_result = result.aegis_result
    policy = aegis_result.policy_result.model_dump()
    provenance = aegis_result.provenance_result.model_dump()
    behaviour = aegis_result.behaviour_result.model_dump()
    risk = aegis_result.risk_result.model_dump()
    decision = aegis_result.model_dump()

    print("\n" + "=" * 60)
    print("AEGIS SECURITY ANALYSIS")
    print("=" * 60)

    print("\nPOLICY")

    print(
        "    Decision :",
        policy.get("decision")
    )

    print(
        "    Reason  :",
        policy.get("reason")
    )

    print("\nPROVENANCE")

    print(
        "    Verified :",
        provenance.get("verified")
    )

    print(
        "    Reason   :",
        provenance.get("reason")
    )

    print("\nBEHAVIOUR")

    print(
        "    Flagged :",
        behaviour.get("flagged")
    )

    print(
        "    Reason  :",
        behaviour.get("deviation_reason")
    )

    print("\nRISK")

    print(
        "    Score :",
        risk.get("score")
    )

    print(
        "    Band :",
        risk.get("band")
    )

    # ---------------------------------------------------------
    # 11. FINAL DECISION
    # ---------------------------------------------------------

    final_decision = result.final_decision

    print("\nFINAL DECISION")

    print(
        "    >>>",
        final_decision.upper()
    )

    print(
        "    Reason:",
        decision.get("reason")
    )

    # ---------------------------------------------------------
    # 12. END
    # ---------------------------------------------------------

    print("\n" + "=" * 60)
    print("        END-TO-END DEMONSTRATION COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()