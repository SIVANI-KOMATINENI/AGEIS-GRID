"""
agents/monitoring_agent.py
The Monitoring and Diagnosis Agent logic.
"""

from typing import Dict, Any
import json
import sys
from pathlib import Path

# Add project root to path when running as script
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from pydantic import ValidationError

import config as cfg
from agents.schemas import MonitoringInput, MonitoringReport
from agents.prompts import MONITORING_SYSTEM_PROMPT


def run_monitoring_agent(
    inputs: MonitoringInput | dict[str, Any]
) -> MonitoringReport:
    """
    Executes the Monitoring Agent using a local Ollama model.
    Falls back to a safe mock if the LLM is unreachable or fails to output correct JSON.
    """
    # 1. Prepare data
    agent_input = MonitoringInput.model_validate(inputs)
    
    # 2. Configure Local LLM with structured output
    llm = ChatOllama(
        base_url=cfg.OLLAMA_BASE_URL,
        model=cfg.OLLAMA_MODEL,
        temperature=0.1,  # Low temperature for analytical task
        format="json"     # Enforce JSON output mode
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", MONITORING_SYSTEM_PROMPT),
        ("human", "Current Observation:\n{current}\n\nRecent History:\n{history}\n\nContext Context:\n{context}\n\nRespond with a JSON object exactly matching the requested schema. Provide ONLY the raw JSON.")
    ])

    chain = prompt | llm
    
    try:
        response = chain.invoke({
            "current": json.dumps(agent_input.current, indent=2),
            "history": json.dumps(agent_input.recent_history, indent=2),
            "context": json.dumps(agent_input.context, indent=2)
        })
        
        # Parse output string to JSON then Pydantic
        content = response.content
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
            
        data = json.loads(content)
        
        # Ensure timestamp matches current observation
        if "timestamp" not in data or not data["timestamp"]:
            data["timestamp"] = agent_input.current.get("timestamp", "unknown")

        data["report_id"] = f"rep_{data['timestamp']}"
        data["run_id"] = agent_input.current.get("run_id", "")
            
        return MonitoringReport(**data)
        
    except Exception as e:
        # Graceful fallback so the pipeline doesn't crash on LLM hiccup
        print(f"[Monitoring Agent] Warning: LLM failed or deviated ({e}). Falling back to hardcoded rule check.")
        return _fallback_rule_based_diagnosis(agent_input)


def _fallback_rule_based_diagnosis(agent_input: MonitoringInput) -> MonitoringReport:
    """A simple rule-based fallback if the LLM isn't running or times out."""
    curr = agent_input.current
    timestamp = curr.get("timestamp", "unknown")
    
    # Simple check for overheating battery (the main scenario in the spec)
    if curr.get("battery_temperature_c", 30.0) > 60.0:
        return MonitoringReport(
            run_id=curr.get("run_id", ""),
            report_id=f"rep_{timestamp}",
            timestamp=timestamp,
            status="ANOMALY",
            severity="HIGH",
            issue="Battery temperature exceeded critical safe limit.",
            evidence={"battery_temperature_c": curr.get("battery_temperature_c")},
            recommended_action="Isolate battery immediately.",
            confidence=1.0
        )
        
    return MonitoringReport(
        run_id=curr.get("run_id", ""),
        report_id=f"rep_{timestamp}",
        timestamp=timestamp,
        status="NORMAL",
        severity="NONE",
        issue=None,
        evidence={"battery_temperature_c": curr.get("battery_temperature_c")},
        recommended_action="Maintain normal operations.",
        confidence=1.0
    )


if __name__ == "__main__":
    # Test script for Milestone 3 part 1
    print("Testing Monitoring Agent (requires Ollama running)...")
    
    test_input = {
        "current": {
            "timestamp": "12:00",
            "voltage_pu": 1.02,
            "load_kw": 45.0,
            "solar_kw": 10.0,
            "battery_soc_pct": 50.0,
            "battery_temperature_c": 92.0,  # Critical anomaly inserted here
            "transformer_loading_pct": 12.0
        },
        "recent_history": [],
        "context": {"battery_normal_range_c": [20, 50]}
    }
    
    report = run_monitoring_agent(test_input)
    print("\n--- Diagnostic Report ---")
    print(report.model_dump_json(indent=2))
