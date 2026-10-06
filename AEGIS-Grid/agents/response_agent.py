"""
agents/response_agent.py
The Response and Maintenance Agent.

Architecture:
    MonitoringReport
         |
         v
    [LLM Proposal] --> raw LLM output (may fail)
         |
         v
    [Action Sanitization Layer]
      - Clamp action_type to allowed Literal set
      - Clamp target to known component names
      - Force claimed_authorization = report_id (never trust LLM)
      - Proportionality check: severity NONE -> block HIGH actions
      - Rate limiting: prevent duplicate severe actions
         |
         v
    ProposedAction (validated, sanitised)
"""

import json
import sys
from pathlib import Path
from typing import Any, Optional, Dict, List

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate

import config as cfg
from agents.schemas import ResponseInput, ProposedAction, MonitoringReport
from agents.prompts import RESPONSE_SYSTEM_PROMPT


# ── Action Sanitization Constants ─────────────────────────────────────────────

VALID_ACTION_TYPES = {
    "ISOLATE_BATTERY", "REDUCE_LOAD", "SHUTDOWN_LOAD",
    "MAINTAIN_STATUS", "INSPECT", "LOG_WARNING", "INVESTIGATE"
}

VALID_TARGETS = {"battery_1", "critical_load", "load_1", "none", "unknown"}

# Maps keywords in issues to appropriate action types
ISSUE_TO_ACTION_MAP = {
    "battery": {"action_type": "ISOLATE_BATTERY", "target": "battery_1"},
    "temperature": {"action_type": "ISOLATE_BATTERY", "target": "battery_1"},
    "overheat": {"action_type": "ISOLATE_BATTERY", "target": "battery_1"},
    "voltage": {"action_type": "INVESTIGATE", "target": "unknown"},
    "transformer": {"action_type": "REDUCE_LOAD", "target": "load_1"},
    "overload": {"action_type": "REDUCE_LOAD", "target": "load_1"},
    "soc": {"action_type": "INSPECT", "target": "battery_1"},
}

SEVERITY_TO_PRIORITY = {
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "NONE": "LOW",
}

# Rate limiting state (in-memory, resets per process)
_recent_severe_actions: List[str] = []
MAX_CONSECUTIVE_SEVERE = 3


# ── Deterministic Rule-Based Response ─────────────────────────────────────────

def _deterministic_response(report: MonitoringReport) -> ProposedAction:
    """
    Pure rule-based action proposal derived directly from the monitoring report.
    Used as both fallback and as a baseline to compare against the LLM.
    """
    action_id = "act_%s" % report.timestamp
    priority = SEVERITY_TO_PRIORITY.get(report.severity, "LOW")

    if report.status == "NORMAL" or report.severity == "NONE":
        return ProposedAction(
            action_id=action_id,
            run_id=report.run_id,
            action_type="MAINTAIN_STATUS",
            target="none",
            reason="System operating normally. No action required.",
            priority="LOW",
            claimed_authorization=report.report_id
        )

    # Match issue keywords to appropriate actions
    issue_lower = (report.issue or "").lower()
    recommended_lower = (report.recommended_action or "").lower()
    combined_text = issue_lower + " " + recommended_lower

    for keyword, mapping in ISSUE_TO_ACTION_MAP.items():
        if keyword in combined_text:
            return ProposedAction(
                action_id=action_id,
                run_id=report.run_id,
                action_type=mapping["action_type"],
                target=mapping["target"],
                reason="Rule-based: %s" % (report.issue or "Anomaly detected"),
                priority=priority,
                claimed_authorization=report.report_id
            )

    # Generic anomaly response
    return ProposedAction(
        action_id=action_id,
        run_id=report.run_id,
        action_type="INVESTIGATE",
        target="unknown",
        reason="Rule-based: Anomaly detected but cause unclear. %s" % (report.issue or ""),
        priority=priority,
        claimed_authorization=report.report_id
    )


# ── LLM Caller ────────────────────────────────────────────────────────────────

def _call_llm_response(report: MonitoringReport, current_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Calls the Ollama LLM for a response proposal. Returns dict on success, None on failure."""
    try:
        llm = ChatOllama(
            base_url=cfg.OLLAMA_BASE_URL,
            model=cfg.OLLAMA_MODEL,
            temperature=0.1,
            format="json"
        )

        prompt = ChatPromptTemplate.from_messages([
            ("system", RESPONSE_SYSTEM_PROMPT),
            ("human",
             "Diagnostic Report:\n{report}\n\n"
             "Current Microgrid State:\n{state}\n\n"
             "Important output rules:\n"
             "1. action_type MUST be one of: ISOLATE_BATTERY, REDUCE_LOAD, "
             "SHUTDOWN_LOAD, MAINTAIN_STATUS, INSPECT, LOG_WARNING, INVESTIGATE\n"
             "2. target MUST be one of: battery_1, critical_load, load_1, none, unknown\n"
             "3. claimed_authorization MUST be: {report_id}\n"
             "4. Return ONLY a JSON object.\n")
        ])

        chain = prompt | llm
        response = chain.invoke({
            "report": report.model_dump_json(indent=2),
            "state": json.dumps(current_state, indent=2),
            "report_id": report.report_id
        })

        content = response.content
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()

        return json.loads(content)

    except Exception as e:
        print("[Response Agent] LLM call failed: %s" % str(e))
        return None


# ── Sanitization Layer ────────────────────────────────────────────────────────

def _sanitize_action(
    llm_data: Optional[Dict[str, Any]],
    rule_action: ProposedAction,
    report: MonitoringReport
) -> ProposedAction:
    """
    Takes raw LLM output and the deterministic baseline, and produces
    a validated, sanitised ProposedAction.
    """
    if llm_data is None:
        return rule_action

    # 1. Force deterministic IDs (never trust LLM for these)
    llm_data["action_id"] = "act_%s" % report.timestamp
    llm_data["run_id"] = report.run_id
    llm_data["claimed_authorization"] = report.report_id

    # 2. Clamp action_type
    raw_type = str(llm_data.get("action_type", "")).upper().strip()
    if raw_type not in VALID_ACTION_TYPES:
        # Try fuzzy match
        for valid in VALID_ACTION_TYPES:
            if valid in raw_type or raw_type in valid:
                raw_type = valid
                break
        else:
            # Fall back to rule-based action
            raw_type = rule_action.action_type
    llm_data["action_type"] = raw_type

    # 3. Clamp target
    raw_target = str(llm_data.get("target", "unknown")).lower().strip()
    if raw_target not in VALID_TARGETS:
        # Try partial match
        for valid in VALID_TARGETS:
            if valid in raw_target or raw_target in valid:
                raw_target = valid
                break
        else:
            raw_target = rule_action.target
    llm_data["target"] = raw_target

    # 4. Clamp priority
    raw_priority = str(llm_data.get("priority", "LOW")).upper().strip()
    if raw_priority not in {"LOW", "MEDIUM", "HIGH"}:
        raw_priority = SEVERITY_TO_PRIORITY.get(report.severity, "LOW")
    llm_data["priority"] = raw_priority

    # 5. Proportionality check
    # If monitoring says NORMAL/NONE but LLM proposes HIGH, demote to MEDIUM
    if report.severity in ("NONE", "LOW") and llm_data["priority"] == "HIGH":
        llm_data["priority"] = "MEDIUM"
        llm_data["reason"] = "(Demoted from HIGH) " + str(llm_data.get("reason", ""))

    # If monitoring says NORMAL but LLM proposes destructive action, override
    if report.status == "NORMAL" and llm_data["action_type"] in ("SHUTDOWN_LOAD", "ISOLATE_BATTERY"):
        return rule_action  # Fall back to MAINTAIN_STATUS

    # 6. Rate limiting check
    global _recent_severe_actions
    if llm_data["priority"] == "HIGH":
        _recent_severe_actions.append(llm_data["action_type"])
        if len(_recent_severe_actions) > MAX_CONSECUTIVE_SEVERE:
            _recent_severe_actions.pop(0)

        # If last N actions were all HIGH, something is suspicious
        if (len(_recent_severe_actions) >= MAX_CONSECUTIVE_SEVERE and
                all(a == llm_data["action_type"] for a in _recent_severe_actions[-MAX_CONSECUTIVE_SEVERE:])):
            llm_data["reason"] = "(Rate limited: repeated severe action) " + str(llm_data.get("reason", ""))
            llm_data["priority"] = "MEDIUM"
    else:
        # Reset rate limiter on non-severe actions
        if _recent_severe_actions:
            _recent_severe_actions.clear()

    try:
        return ProposedAction(**llm_data)
    except Exception:
        # If Pydantic validation still fails, use the rule-based action
        return rule_action


# ── Public Entry Point ────────────────────────────────────────────────────────

def run_response_agent(inputs: ResponseInput | dict) -> ProposedAction:
    """
    Runs the full response pipeline:
    1. Deterministic rule-based response (always runs)
    2. LLM proposal (may fail)
    3. Sanitize & validate
    """
    agent_input = ResponseInput.model_validate(inputs)
    report = agent_input.diagnostic_report

    # Step 1: Deterministic baseline
    rule_action = _deterministic_response(report)

    # Step 2: LLM proposal
    llm_data = _call_llm_response(report, agent_input.current_state)

    # Step 3: Sanitize
    action = _sanitize_action(llm_data, rule_action, report)

    return action


if __name__ == "__main__":
    print("=" * 60)
    print("Response Agent - Deterministic + Sanitized Test")
    print("=" * 60)

    # Test 1: HIGH severity -> ISOLATE_BATTERY
    print("\nTest 1: High severity battery issue")
    report1 = MonitoringReport(
        report_id="rep_12:00", timestamp="12:00", status="ANOMALY",
        severity="HIGH", issue="Battery temperature critically high (92.0 C).",
        evidence={"battery_temperature_c": 92.0},
        recommended_action="Isolate battery immediately.", confidence=1.0
    )
    action1 = run_response_agent({
        "diagnostic_report": report1.model_dump(),
        "current_state": {"battery_temperature_c": 92.0}
    })
    print("  Action: %s | Target: %s | Priority: %s" % (
        action1.action_type, action1.target, action1.priority))
    print("  Auth: %s" % action1.claimed_authorization)
    assert action1.claimed_authorization == "rep_12:00"

    # Test 2: NORMAL -> MAINTAIN_STATUS
    print("\nTest 2: Normal operation")
    report2 = MonitoringReport(
        report_id="rep_12:01", timestamp="12:01", status="NORMAL",
        severity="NONE", evidence={}, confidence=0.9
    )
    action2 = run_response_agent({
        "diagnostic_report": report2.model_dump(),
        "current_state": {"battery_temperature_c": 30.0}
    })
    print("  Action: %s | Target: %s | Priority: %s" % (
        action2.action_type, action2.target, action2.priority))
    assert action2.action_type == "MAINTAIN_STATUS"
    assert action2.priority == "LOW"

    print("\n[OK] All response agent tests passed!")