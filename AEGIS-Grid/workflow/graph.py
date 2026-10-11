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

from datetime import datetime
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
    get_active_session_id,
    insert_observation,
    insert_agent_message,
    insert_attack_event,
    insert_aegis_decision,
    query_recent_observations,
    record_observation_with_replay_check,
    persist_decision_and_consume_report,
    sync_neo4j_outbox,
)

from database.models import (
    ObservationRow,
    AgentMessageRow,
    AttackEventRow,
    AEGISDecisionRow,
    ReplayCheckResult,
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
    session_id: Optional[str]
    execution_timestamp: Optional[str]
    demo_scenario: Optional[str]
    attack_context: AttackContext
    replay_result: ReplayCheckResult
    monitoring_context: Dict[str, Any]
    diagnostic_report: MonitoringReport
    proposed_action: ProposedAction
    policy_result: PolicyResult
    provenance_result: ProvenanceResult
    behaviour_result: BehaviourResult
    risk_result: RiskResult
    workflow_result: WorkflowResult
    personnel_registry: Optional[Any]
    now: Optional[Any]


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

    session_id = (
        state.get("session_id")
        or obs.get("session_id")
        or get_active_session_id()
    )
    execution_timestamp = (
        state.get("execution_timestamp")
        or obs.get("execution_timestamp")
        or datetime.now().isoformat()
    )

    observation_row = ObservationRow(
        **{
            k: v
            for k, v in modified_obs.items()
            if k in ObservationRow.model_fields
            and k not in ("session_id", "execution_timestamp")
        },
        session_id=session_id,
        execution_timestamp=execution_timestamp,
    )

    replay_result = record_observation_with_replay_check(observation_row)

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
        "session_id": session_id,
        "execution_timestamp": execution_timestamp,
        "attack_context": attack_context,
        "replay_result": replay_result,
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
    if not getattr(report, "session_id", None):
        report.session_id = state.get("session_id") or ""

    # ---------------------------------------------------------
    # CROSS-AGENT ATTACK
    # ---------------------------------------------------------

    if state["attack_context"].attack_type == "cross_agent":

        report = apply_cross_agent(
            report
        )
        if not getattr(report, "session_id", None):
            report.session_id = state.get("session_id") or ""

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
    if not getattr(action, "session_id", None):
        action.session_id = state.get("session_id") or getattr(report, "session_id", "") or ""

    # ---------------------------------------------------------
    # AUTHORITY SPOOFING
    # ---------------------------------------------------------

    if state["attack_context"].attack_type == "authority_spoofing":

        action = apply_authority_spoofing(
            action
        )
        if not getattr(action, "session_id", None):
            action.session_id = state.get("session_id") or getattr(report, "session_id", "") or ""

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
        session_id=state.get("session_id") or action.session_id,
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
    report = state.get("diagnostic_report")
    obs = state.get("observation", {})
    context = {
        "battery_temperature_c": obs.get("battery_temperature_c"),
        "voltage_pu": obs.get("voltage_pu"),
        "report_status": getattr(report, "status", None) or (report.get("status") if isinstance(report, dict) else None),
        "report_severity": getattr(report, "severity", None) or (report.get("severity") if isinstance(report, dict) else None),
    }

    personnel_registry = state.get("personnel_registry")
    now = state.get("now")

    try:
        result = verify_policy(
            action,
            context=context,
            personnel_registry=personnel_registry,
            now=now,
        )
    except TypeError:
        try:
            result = verify_policy(action, context=context)
        except TypeError:
            result = verify_policy(action)

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
    session_id = (
        state.get("session_id")
        or getattr(action, "session_id", "")
        or ""
    )
    if not getattr(action, "session_id", None):
        action.session_id = session_id

    personnel_registry = state.get("personnel_registry")
    now = state.get("now")

    try:
        result = verify_provenance(
            action,
            session_id=session_id,
            personnel_registry=personnel_registry,
            now=now,
        )
    except TypeError:
        result = verify_provenance(action)

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
        behaviour,
        state.get("replay_result"),
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
    session_id = (
        state.get("session_id")
        or getattr(action, "session_id", "")
        or get_active_session_id()
    )
    action_digest = getattr(action, "action_digest", "")

    # ---------------------------------------------------------
    # ATOMIC REPORT CONSUMPTION & DECISION PERSISTENCE (Phase B.3)
    # ---------------------------------------------------------

    is_personnel = (
        getattr(action, "authorization_evidence", None) is not None
        and getattr(action.authorization_evidence, "token_type", None) == "PERSONNEL_CREDENTIAL"
    )

    report_id_to_consume = (
        action.claimed_authorization
        if (decision.final_decision == "allow" and action.claimed_authorization and not is_personnel)
        else None
    )

    personnel_evidence_to_consume = (
        action.authorization_evidence
        if (decision.final_decision == "allow" and is_personnel)
        else None
    )

    outbox_payload = {
        "aegis_decision": decision.model_dump(),
        "action_digest": action_digest,
    }

    effective_provenance = (
        decision.provenance_result
        if hasattr(decision, "provenance_result") and decision.provenance_result is not None
        else provenance
    )

    row = AEGISDecisionRow(
        run_id=state["run_id"],
        session_id=session_id,
        timestamp=timestamp,
        action_id=action.action_id,
        policy_result=policy.model_dump_json(),
        provenance_result=effective_provenance.model_dump_json(),
        behaviour_flag=1 if behaviour.flagged else 0,
        risk_score=risk.score,
        final_decision=decision.final_decision,
        reason=decision.reason,
        human_reviewer=None,
        is_injected_attack=int(state["attack_context"].is_injected_attack),
        attack_type=state["attack_context"].attack_type
    )

    try:
        import inspect
        from database.sqlite import consume_report_authorization
        if report_id_to_consume and hasattr(consume_report_authorization, "side_effect") and consume_report_authorization.side_effect is not None:
            consume_report_authorization(
                report_id_to_consume,
                action.action_id,
                session_id,
                action.run_id,
            )

        persist_kwargs = {
            "decision_row": row,
            "report_id": report_id_to_consume,
            "action_digest": action_digest,
            "outbox_payload": outbox_payload,
        }
        if personnel_evidence_to_consume is not None:
            try:
                sig = inspect.signature(persist_decision_and_consume_report)
                if "personnel_evidence" in sig.parameters or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()):
                    persist_kwargs["personnel_evidence"] = personnel_evidence_to_consume
            except Exception:
                persist_kwargs["personnel_evidence"] = personnel_evidence_to_consume

        success, decision_id = persist_decision_and_consume_report(**persist_kwargs)
        if not success:
            # Concurrent race condition or report/credential already claimed
            if is_personnel:
                nonce_val = getattr(action.authorization_evidence, "nonce", "unknown")
                pid_val = getattr(action.authorization_evidence, "personnel_id", "unknown")
                provenance_fail = ProvenanceResult(
                    verified=False,
                    trace_length=0,
                    status="credential_reused",
                    reason=(
                        f"Authorization consumption failed: personnel credential (nonce '{nonce_val}') "
                        f"for '{pid_val}' was already consumed (concurrent replay prevented)."
                    ),
                    auth_type="personnel",
                    personnel_id=pid_val,
                )
                decision = FinalDecision(
                    action=action,
                    policy_result=policy,
                    provenance_result=provenance_fail,
                    behaviour_result=behaviour,
                    risk_result=risk,
                    final_decision="block",
                    reason=f"Personnel credential (nonce '{nonce_val}') was already consumed (concurrent replay prevented).",
                    run_id=state["run_id"],
                )
            else:
                provenance_fail = ProvenanceResult(
                    verified=False,
                    trace_length=0,
                    status="report_reused",
                    reason=f"Authorization consumption failed: report '{action.claimed_authorization}' was already consumed in session '{session_id}'."
                )
                decision = FinalDecision(
                    action=action,
                    policy_result=policy,
                    provenance_result=provenance_fail,
                    behaviour_result=behaviour,
                    risk_result=risk,
                    final_decision="block",
                    reason=f"Report '{action.claimed_authorization}' was already consumed in session '{session_id}' (concurrent replay prevented).",
                    run_id=state["run_id"],
                )
            # Atomically persist the converted BLOCK decision
            block_row = AEGISDecisionRow(
                run_id=state["run_id"],
                session_id=session_id,
                timestamp=timestamp,
                action_id=action.action_id,
                policy_result=policy.model_dump_json(),
                provenance_result=provenance_fail.model_dump_json(),
                behaviour_flag=1 if behaviour.flagged else 0,
                risk_score=risk.score,
                final_decision=decision.final_decision,
                reason=decision.reason,
                human_reviewer=None,
                is_injected_attack=int(state["attack_context"].is_injected_attack),
                attack_type=state["attack_context"].attack_type
            )
            outbox_payload["aegis_decision"] = decision.model_dump()
            persist_decision_and_consume_report(
                decision_row=block_row,
                report_id=None,
                action_digest=action_digest,
                outbox_payload=outbox_payload,
            )
    except Exception as e:
        # Database failure during consumption/persistence: FAIL-CLOSED
        provenance_fail = ProvenanceResult(
            verified=False,
            trace_length=0,
            status="database_error",
            reason=f"Authorization consumption/persistence failed due to database error: {e}"
        )
        decision = FinalDecision(
            action=action,
            policy_result=policy,
            provenance_result=provenance_fail,
            behaviour_result=behaviour,
            risk_result=risk,
            final_decision="block",
            reason=f"Database failure during authorization consumption (fail-closed): {e}",
            run_id=state["run_id"],
        )
        # Attempt to record fail-closed block decision if database is reachable
        try:
            fail_row = AEGISDecisionRow(
                run_id=state["run_id"],
                session_id=session_id,
                timestamp=timestamp,
                action_id=action.action_id,
                policy_result=policy.model_dump_json(),
                provenance_result=provenance_fail.model_dump_json(),
                behaviour_flag=1 if behaviour.flagged else 0,
                risk_score=risk.score,
                final_decision=decision.final_decision,
                reason=decision.reason,
                human_reviewer=None,
                is_injected_attack=int(state["attack_context"].is_injected_attack),
                attack_type=state["attack_context"].attack_type
            )
            outbox_payload["aegis_decision"] = decision.model_dump()
            persist_decision_and_consume_report(
                decision_row=fail_row,
                report_id=None,
                action_digest=action_digest,
                outbox_payload=outbox_payload,
            )
        except Exception:
            pass

    # Discard non-allowed action from trusted behavioural history (fail-closed baseline integrity)
    if decision.final_decision != "allow":
        try:
            from aegis.behaviour import discard_untrusted_action
            discard_untrusted_action(action.action_id, agent=action.sender_agent or "response_agent")
        except Exception:
            pass


    # ---------------------------------------------------------
    # STORE TRACE IN NEO4J / FLUSH OUTBOX
    # ---------------------------------------------------------

    neo = get_neo4j_client()

    synced = 0
    try:
        synced = sync_neo4j_outbox(neo4j_client=neo)
    except Exception as e:
        logger.error(f"Outbox sync to Neo4j deferred: {e}")

    if synced == 0:
        try:
            neo.log_aegis_decision(
                action_id=action.action_id,
                run_id=state["run_id"],
                aegis_decision=decision.model_dump(),
                session_id=session_id,
                action_digest=action_digest,
            )
        except Exception as e:
            logger.error(f"Direct log_aegis_decision call failed: {e}")

    # Console output
    print(
        f"[{timestamp}] AEGIS: "
        f"Action {action.action_type} "
        f"on {action.target} "
        f"-> {decision.final_decision.upper()} "
        f"(Reason: {decision.reason})"
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