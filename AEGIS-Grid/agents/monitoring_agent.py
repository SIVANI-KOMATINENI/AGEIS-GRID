"""
agents/monitoring_agent.py
The Monitoring and Diagnosis Agent.

Architecture:
    Raw Observation
         |
         v
    [Deterministic Rule Check] --> rule_diagnosis (always runs, fast)
         |
         v
    [LLM Analysis] --> llm_diagnosis (may fail, richer reasoning)
         |
         v
    [Validation & Merge Layer]
      - LLM agrees with rules: use LLM output (better reasoning text)
      - LLM contradicts rules on critical metrics: override with rules
      - LLM fails entirely: use rule output directly
         |
         v
    MonitoringReport (validated, deterministic-backed)
"""

from typing import Dict, Any, List, Optional, Tuple
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate

import config as cfg
from agents.schemas import MonitoringInput, MonitoringReport
from agents.prompts import MONITORING_SYSTEM_PROMPT


# ── Deterministic Rule Engine ─────────────────────────────────────────────────

# Thresholds (centralised for easy tuning)
THRESHOLDS = {
    "battery_temp_high_warn":    50.0,
    "battery_temp_high_crit":    70.0,
    "battery_temp_low_warn":     15.0,
    "voltage_low_warn":          0.95,
    "voltage_low_crit":          0.90,
    "voltage_high_warn":         1.05,
    "voltage_high_crit":         1.10,
    "trafo_load_warn":           80.0,
    "trafo_load_crit":           100.0,
    "soc_low_crit":              15.0,
    "soc_high_warn":             95.0,
    "temp_rapid_change":         10.0,   # degrees per minute
}


def _run_deterministic_rules(
    current: Dict[str, Any],
    recent_history: List[Dict[str, Any]]
) -> Tuple[str, str, List[str], Dict[str, Any]]:
    """
    Runs all deterministic rules against the observation.
    Returns (status, severity, issues_list, evidence_dict).
    Severity hierarchy: HIGH > MEDIUM > LOW > NONE.
    """
    issues = []
    evidence = {}
    max_severity = "NONE"
    severity_rank = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}

    def upgrade(sev: str, issue: str, key: str, val: Any):
        nonlocal max_severity
        issues.append(issue)
        evidence[key] = val
        if severity_rank.get(sev, 0) > severity_rank.get(max_severity, 0):
            max_severity = sev

    temp = current.get("battery_temperature_c", 30.0)
    voltage = current.get("voltage_pu", 1.0)
    trafo = current.get("transformer_loading_pct", 0.0)
    soc = current.get("battery_soc_pct", 50.0)

    # Rule 1: Battery overheat
    if temp > THRESHOLDS["battery_temp_high_crit"]:
        upgrade("HIGH", "Battery temperature critically high (%.1f C > %.0f C threshold)." % (temp, THRESHOLDS["battery_temp_high_crit"]),
                "battery_temperature_c", temp)
    elif temp > THRESHOLDS["battery_temp_high_warn"]:
        upgrade("MEDIUM", "Battery temperature elevated (%.1f C > %.0f C warning)." % (temp, THRESHOLDS["battery_temp_high_warn"]),
                "battery_temperature_c", temp)

    # Rule 2: Battery overcool
    if temp < THRESHOLDS["battery_temp_low_warn"]:
        upgrade("MEDIUM", "Battery temperature below safe minimum (%.1f C < %.0f C)." % (temp, THRESHOLDS["battery_temp_low_warn"]),
                "battery_temperature_c", temp)

    # Rule 3: Undervoltage
    if voltage < THRESHOLDS["voltage_low_crit"]:
        upgrade("HIGH", "Critical undervoltage (%.4f pu < %.2f pu)." % (voltage, THRESHOLDS["voltage_low_crit"]),
                "voltage_pu", voltage)
    elif voltage < THRESHOLDS["voltage_low_warn"]:
        upgrade("MEDIUM", "Voltage below nominal (%.4f pu < %.2f pu)." % (voltage, THRESHOLDS["voltage_low_warn"]),
                "voltage_pu", voltage)

    # Rule 4: Overvoltage
    if voltage > THRESHOLDS["voltage_high_crit"]:
        upgrade("HIGH", "Critical overvoltage (%.4f pu > %.2f pu)." % (voltage, THRESHOLDS["voltage_high_crit"]),
                "voltage_pu", voltage)
    elif voltage > THRESHOLDS["voltage_high_warn"]:
        upgrade("MEDIUM", "Voltage above nominal (%.4f pu > %.2f pu)." % (voltage, THRESHOLDS["voltage_high_warn"]),
                "voltage_pu", voltage)

    # Rule 5: Transformer overload
    if trafo > THRESHOLDS["trafo_load_crit"]:
        upgrade("HIGH", "Transformer critically overloaded (%.1f%% > %.0f%%)." % (trafo, THRESHOLDS["trafo_load_crit"]),
                "transformer_loading_pct", trafo)
    elif trafo > THRESHOLDS["trafo_load_warn"]:
        upgrade("MEDIUM", "Transformer loading elevated (%.1f%% > %.0f%%)." % (trafo, THRESHOLDS["trafo_load_warn"]),
                "transformer_loading_pct", trafo)

    # Rule 6: SoC critical low
    if soc < THRESHOLDS["soc_low_crit"]:
        upgrade("HIGH", "Battery SoC critically low (%.1f%% < %.0f%%)." % (soc, THRESHOLDS["soc_low_crit"]),
                "battery_soc_pct", soc)

    # Rule 7: SoC dangerously high
    if soc > THRESHOLDS["soc_high_warn"]:
        upgrade("MEDIUM", "Battery SoC unusually high (%.1f%% > %.0f%%)." % (soc, THRESHOLDS["soc_high_warn"]),
                "battery_soc_pct", soc)

    # Rule 8: Rapid temperature change (needs history)
    if recent_history:
        prev_temp = recent_history[-1].get("battery_temperature_c", temp)
        delta = abs(temp - prev_temp)
        if delta > THRESHOLDS["temp_rapid_change"]:
            upgrade("HIGH", "Rapid battery temp change (%.1f C in 1 step, prev=%.1f C)." % (delta, prev_temp),
                    "temp_delta", delta)

    status = "ANOMALY" if max_severity != "NONE" else "NORMAL"
    return status, max_severity, issues, evidence


def _build_recommended_action(severity: str, issues: List[str]) -> Optional[str]:
    """Maps rule-detected severity to a recommended action string."""
    combined = " ".join(issues).lower()
    if severity == "HIGH":
        if "battery" in combined and "temperature" in combined:
            return "Isolate battery immediately."
        if "voltage" in combined:
            return "Investigate voltage anomaly. Consider load shedding."
        if "transformer" in combined:
            return "Reduce load to prevent transformer damage."
        return "Immediate investigation required."
    elif severity == "MEDIUM":
        return "Monitor closely and prepare for corrective action."
    return None


# ── LLM Caller ────────────────────────────────────────────────────────────────

def _call_llm(agent_input: MonitoringInput) -> Optional[Dict[str, Any]]:
    """
    Calls the Ollama LLM. Returns parsed dict on success, None on failure.
    """
    try:
        llm = ChatOllama(
            base_url=cfg.OLLAMA_BASE_URL,
            model=cfg.OLLAMA_MODEL,
            temperature=0.1,
            format="json"
        )

        prompt = ChatPromptTemplate.from_messages([
            ("system", MONITORING_SYSTEM_PROMPT),
            ("human",
             "Current Observation:\n{current}\n\n"
             "Recent History:\n{history}\n\n"
             "Context:\n{context}\n\n"
             "Respond with a JSON object. Provide ONLY the raw JSON.")
        ])

        chain = prompt | llm
        response = chain.invoke({
            "current": json.dumps(agent_input.current, indent=2),
            "history": json.dumps(agent_input.recent_history, indent=2),
            "context": json.dumps(agent_input.context, indent=2)
        })

        content = response.content
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()

        return json.loads(content)

    except Exception as e:
        print("[Monitoring Agent] LLM call failed: %s" % str(e))
        return None


# ── Validation & Merge Layer ──────────────────────────────────────────────────

VALID_STATUSES = {"NORMAL", "ANOMALY"}
VALID_SEVERITIES = {"NONE", "LOW", "MEDIUM", "HIGH"}
SEVERITY_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


def _merge_diagnoses(
    rule_status: str, rule_severity: str, rule_issues: List[str],
    rule_evidence: Dict[str, Any], rule_action: Optional[str],
    llm_data: Optional[Dict[str, Any]],
    timestamp: str, run_id: str
) -> MonitoringReport:
    """
    Merges rule-based and LLM-based diagnoses.
    Rules always win on safety-critical determinations.
    LLM enriches reasoning text when it agrees.
    """
    report_id = "rep_%s" % timestamp

    # If LLM failed entirely, use pure rule output
    if llm_data is None:
        return MonitoringReport(
            run_id=run_id,
            report_id=report_id,
            timestamp=timestamp,
            status=rule_status,
            severity=rule_severity,
            issue="; ".join(rule_issues) if rule_issues else None,
            evidence=rule_evidence,
            recommended_action=rule_action,
            confidence=1.0  # Rules are deterministic
        )

    # Normalise LLM outputs
    llm_status = str(llm_data.get("status", "NORMAL")).upper().strip()
    llm_severity = str(llm_data.get("severity", "NONE")).upper().strip()

    # Fix common LLM mistakes
    if llm_status == "ABNORMAL":
        llm_status = "ANOMALY"
    if llm_status not in VALID_STATUSES:
        llm_status = rule_status
    if llm_severity not in VALID_SEVERITIES:
        llm_severity = rule_severity

    # MERGE LOGIC:
    # 1. If rules detected HIGH and LLM says NORMAL -> rules win (LLM missed it)
    # 2. If rules say NORMAL and LLM says ANOMALY -> use LLM but cap at MEDIUM
    #    (LLM might see patterns rules don't, but we don't fully trust it)
    # 3. If both agree -> use LLM reasoning (richer text)

    if SEVERITY_RANK.get(rule_severity, 0) >= SEVERITY_RANK.get("HIGH", 3):
        # Rules found something critical - rules always win
        final_status = rule_status
        final_severity = rule_severity
        final_issues = rule_issues
        final_evidence = rule_evidence
        final_action = rule_action
        confidence = 1.0
    elif rule_status == "NORMAL" and llm_status == "ANOMALY":
        # LLM sees something rules didn't - cautiously trust but cap severity
        final_status = "ANOMALY"
        capped = min(SEVERITY_RANK.get(llm_severity, 1), SEVERITY_RANK.get("MEDIUM", 2))
        final_severity = {0: "NONE", 1: "LOW", 2: "MEDIUM", 3: "HIGH"}.get(capped, "MEDIUM")
        final_issues = [llm_data.get("issue", "LLM-detected anomaly")]
        final_evidence = llm_data.get("evidence", {})
        final_action = llm_data.get("recommended_action", rule_action)
        confidence = min(float(llm_data.get("confidence", 0.5)), 0.7)
    elif rule_status == "ANOMALY" and llm_status == "ANOMALY":
        # Both agree - use LLM reasoning but keep rule severity if higher
        final_status = "ANOMALY"
        if SEVERITY_RANK.get(rule_severity, 0) > SEVERITY_RANK.get(llm_severity, 0):
            final_severity = rule_severity
        else:
            final_severity = llm_severity
        # Combine evidence
        final_evidence = dict(rule_evidence)
        final_evidence.update(llm_data.get("evidence", {}))
        # Use LLM issue text (richer) but append rule issues
        llm_issue = llm_data.get("issue", "")
        final_issues = [llm_issue] if llm_issue else []
        final_issues.extend(rule_issues)
        final_action = llm_data.get("recommended_action", rule_action)
        confidence = float(llm_data.get("confidence", 0.8))
    else:
        # Both say NORMAL
        final_status = "NORMAL"
        final_severity = "NONE"
        final_issues = []
        final_evidence = rule_evidence or llm_data.get("evidence", {})
        final_action = llm_data.get("recommended_action", rule_action)
        confidence = float(llm_data.get("confidence", 0.9))

    return MonitoringReport(
        run_id=run_id,
        report_id=report_id,
        timestamp=timestamp,
        status=final_status,
        severity=final_severity,
        issue="; ".join(final_issues) if final_issues else None,
        evidence=final_evidence,
        recommended_action=final_action,
        confidence=confidence
    )


# ── Public Entry Point ────────────────────────────────────────────────────────

def run_monitoring_agent(inputs: MonitoringInput | dict) -> MonitoringReport:
    """
    Runs the full monitoring pipeline:
    1. Deterministic rule check
    2. LLM analysis
    3. Merge & validate
    """
    agent_input = MonitoringInput.model_validate(inputs)
    timestamp = agent_input.current.get("timestamp", "unknown")
    run_id = agent_input.current.get("run_id", "")

    # Step 1: Deterministic rules (always runs, never fails)
    rule_status, rule_severity, rule_issues, rule_evidence = _run_deterministic_rules(
        agent_input.current, agent_input.recent_history
    )
    rule_action = _build_recommended_action(rule_severity, rule_issues)

    # Step 2: LLM analysis (may fail gracefully)
    llm_data = _call_llm(agent_input)

    # Step 3: Merge
    report = _merge_diagnoses(
        rule_status, rule_severity, rule_issues,
        rule_evidence, rule_action,
        llm_data, timestamp, run_id
    )

    return report


if __name__ == "__main__":
    print("=" * 60)
    print("Monitoring Agent - Deterministic + LLM Test")
    print("=" * 60)

    # Test 1: Clear anomaly (battery overheat)
    print("\nTest 1: Battery overheat (92 C)")
    report1 = run_monitoring_agent({
        "current": {
            "timestamp": "12:00", "voltage_pu": 1.02, "load_kw": 45.0,
            "solar_kw": 10.0, "battery_soc_pct": 50.0,
            "battery_temperature_c": 92.0, "transformer_loading_pct": 12.0
        },
        "recent_history": [],
        "context": {"battery_normal_range_c": [20, 50]}
    })
    print("  Status: %s | Severity: %s | Confidence: %.2f" % (
        report1.status, report1.severity, report1.confidence))
    print("  Issue: %s" % report1.issue)
    assert report1.status == "ANOMALY"
    assert report1.severity == "HIGH"

    # Test 2: Normal operation
    print("\nTest 2: Normal operation")
    report2 = run_monitoring_agent({
        "current": {
            "timestamp": "12:01", "voltage_pu": 1.02, "load_kw": 30.0,
            "solar_kw": 40.0, "battery_soc_pct": 65.0,
            "battery_temperature_c": 35.0, "transformer_loading_pct": 15.0
        },
        "recent_history": [],
        "context": {"battery_normal_range_c": [20, 50]}
    })
    print("  Status: %s | Severity: %s" % (report2.status, report2.severity))
    assert report2.status == "NORMAL"

    # Test 3: Medium severity (elevated temp)
    print("\nTest 3: Elevated temp (55 C)")
    report3 = run_monitoring_agent({
        "current": {
            "timestamp": "12:02", "voltage_pu": 1.01, "load_kw": 30.0,
            "solar_kw": 20.0, "battery_soc_pct": 50.0,
            "battery_temperature_c": 55.0, "transformer_loading_pct": 20.0
        },
        "recent_history": [],
        "context": {"battery_normal_range_c": [20, 50]}
    })
    print("  Status: %s | Severity: %s" % (report3.status, report3.severity))
    assert report3.status == "ANOMALY"
    assert report3.severity == "MEDIUM"

    print("\n[OK] All monitoring agent tests passed!")
