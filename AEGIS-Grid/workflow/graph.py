# """
# workflow/graph.py
# Wires everything together using LangGraph.
# """

# from typing import TypedDict, Dict, Any, Optional
# from langgraph.graph import StateGraph, END

# # Agents
# from agents.schemas import MonitoringInput, MonitoringReport, ResponseInput, ProposedAction
# from agents.monitoring_agent import run_monitoring_agent
# from agents.response_agent import run_response_agent

# # AEGIS Core
# from aegis.policy import verify_policy, PolicyResult
# from aegis.provenance import verify_provenance, ProvenanceResult
# from aegis.behaviour import analyze_behaviour, BehaviourResult
# from aegis.risk import evaluate_risk, RiskResult
# from aegis.controller import make_decision, FinalDecision

# # Attacks
# from attacks.manager import run_attack_manager
# from attacks.cross_agent import apply_cross_agent
# from attacks.authority_spoofing import apply_authority_spoofing

# # DB Logging
# from database.sqlite import (
#     insert_observation, insert_agent_message, insert_attack_event, insert_aegis_decision
# )
# from database.models import ObservationRow, AgentMessageRow, AttackEventRow, AEGISDecisionRow
# from provenance.neo4j_client import get_neo4j_client
# import config as cfg


# class AgentState(TypedDict):
#     """The state shared across all nodes in the workflow."""
#     raw_observation: Dict[str, Any]
#     active_attack_type: Optional[str]
#     is_injected_attack: int
    
#     # Checkpoints
#     observation: Dict[str, Any]     # After attack manager
#     monitoring_input: dict          
#     diagnostic_report: dict         # After Monitoring Agent
#     response_input: dict
#     proposed_action: dict           # After Response Agent
    
#     # AEGIS Results
#     policy_res: dict
#     prov_res: dict
#     behav_res: dict
#     risk_res: dict
#     final_decision: dict


# # ── NODE FUNCTIONS ─────────────────────────────────────────────────────────────

# def get_microgrid_state(state: AgentState):
#     """(Node 1) Fetch state and apply observation-layer attacks."""
#     obs = state["raw_observation"]
#     timestamp = obs["timestamp"]
    
#     # 1. Attack Scenario Manager
#     modified_obs = run_attack_manager(timestamp, obs)
    
#     attack_type = modified_obs.get("attack_type")
#     is_injected = modified_obs.get("is_injected_attack", 0)
    
#     # Log observation to SQLite
#     insert_observation(ObservationRow(**{k: v for k, v in modified_obs.items() if k in ObservationRow.model_fields}))
    
#     if is_injected and attack_type:
#         from database.sqlite import insert_attack_event
#         insert_attack_event(AttackEventRow(
#             attack_type=attack_type,
#             target="observation",
#             start_time=timestamp,
#             end_time=timestamp
#         ))
        
#     return {
#         "observation": modified_obs,
#         "active_attack_type": attack_type,
#         "is_injected_attack": is_injected
#     }

# def monitoring_agent_node(state: AgentState):
#     """(Node 2) Run the monitoring agent LLM."""
#     # Build input
#     from database.sqlite import query_recent_observations
#     recent = query_recent_observations(5)
    
#     minput = {
#         "current": state["observation"],
#         "recent_history": recent,
#         "context": {"battery_normal_range_c": [20, 50], "voltage_nom_pu": 1.0}
#     }
    
#     report = run_monitoring_agent(minput)
    
#     # Cross-Agent attack simulation (Layer B interception)
#     if state["active_attack_type"] == "cross_agent":
#         report = apply_cross_agent(report)
        
#     # Log message
#     insert_agent_message(AgentMessageRow(
#         timestamp=state["observation"]["timestamp"],
#         sender_agent="monitoring_agent",
#         receiver_agent="response_agent",
#         message_content=report.model_dump_json()
#     ))
        
#     return {
#         "monitoring_input": minput,
#         "diagnostic_report": report.model_dump()
#     }

# def response_agent_node(state: AgentState):
#     """(Node 3) Run the response agent LLM."""
#     rep = MonitoringReport(**state["diagnostic_report"])
    
#     rinput = {
#         "diagnostic_report": rep.model_dump(),
#         "current_state": {"battery_temperature_c": state["observation"].get("battery_temperature_c")}
#     }
    
#     action = run_response_agent(rinput)
    
#     # Authority Spoofing attack simulation
#     if state["active_attack_type"] == "authority_spoofing":
#         action = apply_authority_spoofing(action)
        
#     # Log message
#     insert_agent_message(AgentMessageRow(
#         timestamp=state["observation"]["timestamp"],
#         sender_agent="response_agent",
#         receiver_agent="aegis_grid",
#         message_content=action.model_dump_json()
#     ))
        
#     return {
#         "response_input": rinput,
#         "proposed_action": action.model_dump()
#     }

# def aegis_policy_node(state: AgentState):
#     """(Node 4) Policy verification."""
#     action = ProposedAction(**state["proposed_action"])
#     res = verify_policy(action)
#     return {"policy_res": res.model_dump()}

# def aegis_provenance_node(state: AgentState):
#     """(Node 5) Provenance tracing in Neo4j."""
#     action = ProposedAction(**state["proposed_action"])
#     res = verify_provenance(action)
#     return {"prov_res": res.model_dump()}

# def aegis_behaviour_node(state: AgentState):
#     """(Node 6) Behaviour anomaly check."""
#     action = ProposedAction(**state["proposed_action"])
#     res = analyze_behaviour(action)
#     return {"behav_res": res.model_dump()}

# def aegis_risk_node(state: AgentState):
#     """(Node 7) Risk Evaluation."""
#     pol = PolicyResult(**state["policy_res"])
#     prov = ProvenanceResult(**state["prov_res"])
#     beh = BehaviourResult(**state["behav_res"])
    
#     res = evaluate_risk(pol, prov, beh)
#     return {"risk_res": res.model_dump()}

# def decision_controller_node(state: AgentState):
#     """(Node 8) Final Decision and Logging."""
#     action = ProposedAction(**state["proposed_action"])
#     pol = PolicyResult(**state["policy_res"])
#     prov = ProvenanceResult(**state["prov_res"])
#     beh = BehaviourResult(**state["behav_res"])
#     risk = RiskResult(**state["risk_res"])
    
#     decision = make_decision(action, pol, prov, beh, risk)
#     ts = state["observation"]["timestamp"]
    
#     # 1. Log to SQLite
#     row = AEGISDecisionRow(
#         timestamp=ts,
#         action_id=action.action_id,
#         policy_result=pol.model_dump_json(),
#         provenance_result=prov.model_dump_json(),
#         behaviour_flag=1 if beh.flagged else 0,
#         risk_score=risk.score,
#         final_decision=decision.final_decision,
#         reason=decision.reason,
#         human_reviewer=None,
#         is_injected_attack=state["is_injected_attack"],
#         attack_type=state["active_attack_type"]
#     )
#     insert_aegis_decision(row)
    
#     # 2. Log full trace to Neo4j
#     neo = get_neo4j_client()
#     neo.log_full_action_chain(
#         observation=state["observation"],
#         report=state["diagnostic_report"],
#         proposed_action=state["proposed_action"],
#         aegis_decision=decision.model_dump()
#     )
    
#     print(f"[{ts}] AEGIS: Action {action.action_type} on {action.target} -> {decision.final_decision.upper()}")
    
#     return {"final_decision": decision.model_dump()}


# # ── BUILD GRAPH ────────────────────────────────────────────────────────────────

# def build_workflow() -> StateGraph:
#     workflow = StateGraph(AgentState)
    
#     workflow.add_node("microgrid", get_microgrid_state)
#     workflow.add_node("monitor", monitoring_agent_node)
#     workflow.add_node("response", response_agent_node)
#     workflow.add_node("policy", aegis_policy_node)
#     workflow.add_node("provenance", aegis_provenance_node)
#     workflow.add_node("behaviour", aegis_behaviour_node)
#     workflow.add_node("risk", aegis_risk_node)
#     workflow.add_node("decision", decision_controller_node)
    
#     # Wiring sequentially
#     workflow.add_edge("microgrid", "monitor")
#     workflow.add_edge("monitor", "response")
#     workflow.add_edge("response", "policy")
#     workflow.add_edge("policy", "provenance")
#     workflow.add_edge("provenance", "behaviour")
#     workflow.add_edge("behaviour", "risk")
#     workflow.add_edge("risk", "decision")
#     workflow.add_edge("decision", END)
    
#     workflow.set_entry_point("microgrid")
    
#     return workflow.compile()



"""
workflow/graph.py

Wires everything together using LangGraph.
Supports both:
1. Normal/time-based simulation mode
2. Explicit demonstration scenarios
"""

from typing import TypedDict, Dict, Any, Optional, Literal
from uuid import uuid4

from langgraph.graph import StateGraph, END
from pydantic import BaseModel, computed_field

# Agents
from agents.schemas import (
    MonitoringInput,
    MonitoringReport,
    ResponseInput,
    ProposedAction
)
from agents.monitoring_agent import run_monitoring_agent
from agents.response_agent import run_response_agent

# AEGIS Core
from aegis.policy import verify_policy, PolicyResult
from aegis.provenance import verify_provenance, ProvenanceResult
from aegis.behaviour import analyze_behaviour, BehaviourResult
from aegis.risk import evaluate_risk, RiskResult
from aegis.controller import make_decision, FinalDecision

# Attacks
from attacks.manager import run_attack_manager
from attacks.sensor_poisoning import apply_sensor_poisoning
from attacks.cross_agent import apply_cross_agent
from attacks.authority_spoofing import apply_authority_spoofing

# Database
from database.sqlite import (
    insert_observation,
    insert_agent_message,
    insert_attack_event,
    insert_aegis_decision,
    query_recent_observations
)

from database.models import (
    ObservationRow,
    AgentMessageRow,
    AttackEventRow,
    AEGISDecisionRow
)

# Neo4j
from provenance.neo4j_client import get_neo4j_client


class AttackContext(BaseModel):
    is_injected_attack: bool = False
    attack_type: Optional[str] = None


class WorkflowResult(BaseModel):
    aegis_result: FinalDecision

    @computed_field
    @property
    def proposed_action(self) -> ProposedAction:
        return self.aegis_result.action

    @computed_field
    @property
    def final_decision(self) -> Literal["allow", "block", "human_approval"]:
        return self.aegis_result.final_decision


class AgentState(TypedDict, total=False):
    """Canonical state shared by the workflow nodes."""

    observation: Dict[str, Any]
    run_id: str
    demo_scenario: Optional[str]
    attack_context: AttackContext
    monitoring_context: Dict[str, Any]
    diagnostic_report: MonitoringReport
    proposed_action: ProposedAction
    policy_result: PolicyResult
    provenance_result: ProvenanceResult
    behaviour_result: BehaviourResult
    risk_result: RiskResult
    workflow_result: WorkflowResult


# ─────────────────────────────────────────────────────────────────────────────
# NODE 1 — MICROGRID + ATTACK SCENARIO
# ─────────────────────────────────────────────────────────────────────────────

def attack_manager_node(state: AgentState):
    """
    Node 1.

    Receives the raw microgrid observation.

    If an explicit demonstration scenario was selected, that scenario is
    used instead of relying on the clock-based attack schedule.

    In normal mode, the original Attack Scenario Manager remains active.
    """

    run_id = uuid4().hex
    obs = dict(state["observation"])
    obs["run_id"] = run_id
    timestamp = obs["timestamp"]

    demo_scenario = state.get("demo_scenario")

    # ---------------------------------------------------------
    # EXPLICIT DEMONSTRATION MODE
    # ---------------------------------------------------------

    if demo_scenario and demo_scenario != "normal":

        modified_obs = dict(obs)

        modified_obs["is_injected_attack"] = 1
        modified_obs["attack_type"] = demo_scenario

        # Sensor poisoning modifies the observation itself.
        if demo_scenario == "sensor_poisoning":

            modified_obs = apply_sensor_poisoning(modified_obs)

    # ---------------------------------------------------------
    # NORMAL MODE
    # ---------------------------------------------------------

    else:

        # Keep the original 24-hour time-based attack schedule.
        modified_obs = run_attack_manager(
            timestamp,
            obs
        )

    attack_type = modified_obs.get("attack_type")
    is_injected = modified_obs.get(
        "is_injected_attack",
        0
    )

    attack_context = AttackContext(
        is_injected_attack=bool(is_injected),
        attack_type=attack_type
    )

    modified_obs.pop("is_injected_attack", None)
    modified_obs.pop("attack_type", None)

    monitoring_context = {
        "recent_history": query_recent_observations(5),
        "context": {
            "battery_normal_range_c": [20, 50],
            "voltage_nom_pu": 1.0
        }
    }

    # ---------------------------------------------------------
    # STORE OBSERVATION
    # ---------------------------------------------------------

    observation_row = ObservationRow(
        **{
            k: v
            for k, v in modified_obs.items()
            if k in ObservationRow.model_fields
        }
    )

    insert_observation(observation_row)

    # ---------------------------------------------------------
    # STORE ATTACK GROUND TRUTH
    # ---------------------------------------------------------

    if attack_context.is_injected_attack and attack_context.attack_type:

        insert_attack_event(
            AttackEventRow(
                attack_type=attack_context.attack_type,
                target="observation",
                run_id=run_id,
                start_time=timestamp,
                end_time=timestamp
            )
        )

    return {
        "observation": modified_obs,
        "run_id": run_id,
        "attack_context": attack_context,
        "monitoring_context": monitoring_context
    }


# ─────────────────────────────────────────────────────────────────────────────
# NODE 2 — MONITORING AGENT
# ─────────────────────────────────────────────────────────────────────────────

def monitoring_agent_node(state: AgentState):
    """
    Node 2.

    Monitoring Agent receives the current observation and recent history.

    Cross-agent attack is applied here because this attack represents
    modification of the Monitoring Agent's report before it reaches
    the Response Agent.
    """

    monitoring_input = MonitoringInput(
        current=state["observation"],
        recent_history=state["monitoring_context"]["recent_history"],
        context=state["monitoring_context"]["context"]
    )

    # Run Monitoring Agent
    report = run_monitoring_agent(
        monitoring_input
    )

    # ---------------------------------------------------------
    # CROSS-AGENT ATTACK
    # ---------------------------------------------------------

    if state["attack_context"].attack_type == "cross_agent":

        report = apply_cross_agent(
            report
        )

    # ---------------------------------------------------------
    # LOG AGENT MESSAGE
    # ---------------------------------------------------------

    insert_agent_message(
        AgentMessageRow(
            run_id=state["run_id"],
            timestamp=state["observation"]["timestamp"],
            sender_agent="monitoring_agent",
            receiver_agent="response_agent",
            message_content=report.model_dump_json()
        )
    )

    return {
        "diagnostic_report": report
    }


# ─────────────────────────────────────────────────────────────────────────────
# NODE 3 — RESPONSE AGENT
# ─────────────────────────────────────────────────────────────────────────────

def response_agent_node(state: AgentState):
    """
    Node 3.

    Response Agent receives the Monitoring Agent's report and proposes
    an action.

    Authority spoofing is applied here because it represents an attacker
    modifying/spoofing the authority associated with the proposed action.
    """

    report = state["diagnostic_report"]

    response_input = ResponseInput(
        diagnostic_report=report,
        current_state={
            "battery_temperature_c":
                state["observation"].get(
                    "battery_temperature_c"
                )
        }
    )

    # Run Response Agent
    action = run_response_agent(
        response_input
    )

    # ---------------------------------------------------------
    # AUTHORITY SPOOFING
    # ---------------------------------------------------------

    if state["attack_context"].attack_type == "authority_spoofing":

        action = apply_authority_spoofing(
            action
        )

    # ---------------------------------------------------------
    # LOG RESPONSE AGENT MESSAGE
    # ---------------------------------------------------------

    insert_agent_message(
        AgentMessageRow(
            run_id=state["run_id"],
            timestamp=state["observation"]["timestamp"],
            sender_agent="response_agent",
            receiver_agent="aegis_grid",
            message_content=action.model_dump_json()
        )
    )

    neo = get_neo4j_client()
    neo.log_action_provenance(
        observation=state["observation"],
        report=report.model_dump(),
        proposed_action=action.model_dump(),
    )

    return {
        "proposed_action": action
    }


# ─────────────────────────────────────────────────────────────────────────────
# NODE 4 — POLICY
# ─────────────────────────────────────────────────────────────────────────────

def aegis_policy_node(state: AgentState):
    """
    Node 4.

    AEGIS Policy Engine checks whether the proposed action is allowed
    according to the configured rules.
    """

    action = state["proposed_action"]

    result = verify_policy(
        action
    )

    return {
        "policy_result": result
    }


# ─────────────────────────────────────────────────────────────────────────────
# NODE 5 — PROVENANCE
# ─────────────────────────────────────────────────────────────────────────────

def aegis_provenance_node(state: AgentState):
    """
    Node 5.

    AEGIS checks whether the claimed authority associated with the
    proposed action can be verified.
    """

    action = state["proposed_action"]

    result = verify_provenance(
        action
    )

    return {
        "provenance_result": result
    }


# ─────────────────────────────────────────────────────────────────────────────
# NODE 6 — BEHAVIOUR
# ─────────────────────────────────────────────────────────────────────────────

def aegis_behaviour_node(state: AgentState):
    """
    Node 6.

    Checks whether the proposed action is behaviourally unusual.
    """

    action = state["proposed_action"]

    result = analyze_behaviour(
        action
    )

    return {
        "behaviour_result": result
    }


# ─────────────────────────────────────────────────────────────────────────────
# NODE 7 — RISK
# ─────────────────────────────────────────────────────────────────────────────

def aegis_risk_node(state: AgentState):
    """
    Node 7.

    Combines policy, provenance and behaviour results into a risk score.
    """

    policy = state["policy_result"]
    provenance = state["provenance_result"]
    behaviour = state["behaviour_result"]

    result = evaluate_risk(
        policy,
        provenance,
        behaviour
    )

    return {
        "risk_result": result
    }


# ─────────────────────────────────────────────────────────────────────────────
# NODE 8 — FINAL DECISION
# ─────────────────────────────────────────────────────────────────────────────

def decision_controller_node(state: AgentState):
    """
    Node 8.

    Final AEGIS security gate.

    Possible outcomes:
        ALLOW
        BLOCK
        HUMAN_APPROVAL
    """

    action = state["proposed_action"]
    policy = state["policy_result"]
    provenance = state["provenance_result"]
    behaviour = state["behaviour_result"]
    risk = state["risk_result"]

    # Final AEGIS decision
    decision = make_decision(
        action,
        policy,
        provenance,
        behaviour,
        risk
    )

    timestamp = state["observation"]["timestamp"]

    # ---------------------------------------------------------
    # STORE DECISION IN SQLITE
    # ---------------------------------------------------------

    row = AEGISDecisionRow(
        run_id=state["run_id"],
        timestamp=timestamp,
        action_id=action.action_id,
        policy_result=policy.model_dump_json(),
        provenance_result=provenance.model_dump_json(),
        behaviour_flag=1 if behaviour.flagged else 0,
        risk_score=risk.score,
        final_decision=decision.final_decision,
        reason=decision.reason,
        human_reviewer=None,
        is_injected_attack=int(state["attack_context"].is_injected_attack),
        attack_type=state["attack_context"].attack_type
    )

    insert_aegis_decision(row)

    # ---------------------------------------------------------
    # STORE TRACE IN NEO4J
    # ---------------------------------------------------------

    neo = get_neo4j_client()

    neo.log_aegis_decision(
        action_id=action.action_id,
        aegis_decision=decision.model_dump(),
        run_id=state["run_id"],
    )

    # Console output
    print(
        f"[{timestamp}] AEGIS: "
        f"Action {action.action_type} "
        f"on {action.target} "
        f"-> {decision.final_decision.upper()}"
    )

    return {
        "workflow_result": WorkflowResult(aegis_result=decision)
    }


# ─────────────────────────────────────────────────────────────────────────────
# BUILD LANGGRAPH WORKFLOW
# ─────────────────────────────────────────────────────────────────────────────

def build_workflow():

    workflow = StateGraph(
        AgentState
    )

    # Nodes
    workflow.add_node(
        "attack_manager",
        attack_manager_node
    )

    workflow.add_node(
        "monitor",
        monitoring_agent_node
    )

    workflow.add_node(
        "response",
        response_agent_node
    )

    workflow.add_node(
        "policy",
        aegis_policy_node
    )

    workflow.add_node(
        "provenance",
        aegis_provenance_node
    )

    workflow.add_node(
        "behaviour",
        aegis_behaviour_node
    )

    workflow.add_node(
        "risk",
        aegis_risk_node
    )

    workflow.add_node(
        "decision",
        decision_controller_node
    )

    # Sequential execution
    workflow.add_edge(
        "attack_manager",
        "monitor"
    )

    workflow.add_edge(
        "monitor",
        "response"
    )

    workflow.add_edge(
        "response",
        "policy"
    )

    workflow.add_edge(
        "policy",
        "provenance"
    )

    workflow.add_edge(
        "provenance",
        "behaviour"
    )

    workflow.add_edge(
        "behaviour",
        "risk"
    )

    workflow.add_edge(
        "risk",
        "decision"
    )

    workflow.add_edge(
        "decision",
        END
    )

    workflow.set_entry_point(
        "attack_manager"
    )

    return workflow.compile()