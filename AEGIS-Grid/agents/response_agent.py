# """
# agents/response_agent.py
# The Response and Maintenance Agent logic.
# """

# import json
# import sys
# from pathlib import Path

# # Add project root to path when running as script
# _ROOT = Path(__file__).resolve().parent.parent
# sys.path.insert(0, str(_ROOT))

# from langchain_ollama import ChatOllama
# from langchain_core.prompts import ChatPromptTemplate

# import config as cfg
# from agents.schemas import ResponseInput, ProposedAction, MonitoringReport
# from agents.prompts import RESPONSE_SYSTEM_PROMPT


# def run_response_agent(inputs: dict) -> ProposedAction:
#     """
#     Executes the Response Agent using a local Ollama model.
#     Falls back to a safe mock if the LLM is unreachable.
#     """
#     agent_input = ResponseInput(**inputs)
    
#     llm = ChatOllama(
#         base_url=cfg.OLLAMA_BASE_URL,
#         model=cfg.OLLAMA_MODEL,
#         temperature=0.1,  
#         format="json"
#     )

#     prompt = ChatPromptTemplate.from_messages([
#         ("system", RESPONSE_SYSTEM_PROMPT),
#         ("human", "Diagnostic Report:\n{report}\n\nCurrent Microgrid State:\n{state}\n\nRespond with a JSON object exactly matching the requested schema. Use the report timestamp as your claimed_authorization. Provide ONLY the raw JSON.")
#     ])

#     chain = prompt | llm
    
#     try:
#         response = chain.invoke({
#             "report": agent_input.diagnostic_report.model_dump_json(indent=2),
#             "state": json.dumps(agent_input.current_state, indent=2)
#         })
        
#         content = response.content
#         if "```json" in content:
#             content = content.split("```json")[1].split("```")[0].strip()
            
#         data = json.loads(content)
        
#         # Enforce action_id deterministic generation for tracing
#         if "action_id" not in data or not data["action_id"]:
#             data["action_id"] = f"act_{agent_input.diagnostic_report.timestamp}"
            
#         return ProposedAction(**data)
        
#     except Exception as e:
#         print(f"[Response Agent] Warning: LLM failed or deviated ({e}). Falling back to rule-based proposal.")
#         return _fallback_rule_based_response(agent_input)


# def _fallback_rule_based_response(agent_input: ResponseInput) -> ProposedAction:
#     report = agent_input.diagnostic_report
#     action_id = f"act_{report.timestamp}"
    
#     if report.status == "ANOMALY":
#         if "battery" in (report.issue or "").lower() or "overheat" in (report.recommended_action or "").lower():
#             return ProposedAction(
#                 action_id=action_id,
#                 action_type="ISOLATE_BATTERY",
#                 target="battery_1",
#                 reason="Fallback: " + (report.issue or "Battery issue detected."),
#                 priority="HIGH",
#                 claimed_authorization=report.timestamp
#             )
        
#         return ProposedAction(
#             action_id=action_id,
#             action_type="INVESTIGATE",
#             target="unknown",
#             reason="Fallback response for anomaly.",
#             priority="MEDIUM",
#             claimed_authorization=report.timestamp
#         )

#     # Normal state
#     return ProposedAction(
#         action_id=action_id,
#         action_type="MAINTAIN_STATUS",
#         target="none",
#         reason="System operating normally.",
#         priority="LOW",
#         claimed_authorization=report.timestamp
#     )


# if __name__ == "__main__":
#     # Test script for Milestone 3 part 2
#     print("Testing Response Agent (requires Ollama running)...")
    
#     # Mock a high severity report
#     report = MonitoringReport(
#         timestamp="12:00",
#         status="ANOMALY",
#         severity="HIGH",
#         issue="Battery temperature reached 92C.",
#         evidence={"battery_temperature_c": 92.0},
#         recommended_action="Isolate battery immediately.",
#         confidence=0.95
#     )
    
#     test_input = {
#         "diagnostic_report": report.model_dump(),
#         "current_state": {"battery_temperature_c": 92.0, "battery_soc_pct": 50.0}
#     }
    
#     proposal = run_response_agent(test_input)
#     print("\n--- Proposed Action ---")
#     print(proposal.model_dump_json(indent=2))



"""
agents/response_agent.py
The Response and Maintenance Agent logic.
"""

import json
import sys
from pathlib import Path
from typing import Any

# Add project root to path when running as script
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate

import config as cfg

from agents.schemas import ResponseInput, ProposedAction
from agents.prompts import RESPONSE_SYSTEM_PROMPT


def run_response_agent(
    inputs: ResponseInput | dict[str, Any]
) -> ProposedAction:
    """
    Executes the Response Agent using a local Ollama model.

    Falls back to a deterministic rule-based proposal if
    the LLM is unavailable or produces invalid output.
    """

    agent_input = ResponseInput.model_validate(inputs)

    llm = ChatOllama(
        base_url=cfg.OLLAMA_BASE_URL,
        model=cfg.OLLAMA_MODEL,
        temperature=0.1,
        format="json"
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", RESPONSE_SYSTEM_PROMPT),

        (
            "human",
            """
Diagnostic Report:
{report}

Current Microgrid State:
{state}

Important output rules:

1. action_type MUST be one of:
   ISOLATE_BATTERY
   REDUCE_LOAD
   SHUTDOWN_LOAD
   MAINTAIN_STATUS
   INSPECT
   LOG_WARNING
   INVESTIGATE

2. target MUST be exactly one of:
   battery_1
   critical_load
   load_1
   none
   unknown

3. Do not invent target names such as "Affected Battery".

4. claimed_authorization MUST be the report ID provided in the
   diagnostic report.

5. Return ONLY a JSON object matching the ProposedAction schema.
"""
        )
    ])

    chain = prompt | llm

    try:
        report = agent_input.diagnostic_report

        response = chain.invoke({
            "report": report.model_dump_json(indent=2),
            "state": json.dumps(
                agent_input.current_state,
                indent=2
            )
        })

        content = response.content

        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()

        data = json.loads(content)

        # Enforce deterministic identifiers.
        data["action_id"] = f"act_{report.timestamp}"
        data["run_id"] = report.run_id

        # Do not allow the LLM to invent the authorization identifier.
        data["claimed_authorization"] = report.report_id

        return ProposedAction(**data)

    except Exception as e:

        print(
            f"[Response Agent] Warning: LLM failed or produced "
            f"invalid output ({e}). Using rule-based proposal."
        )

        return _fallback_rule_based_response(agent_input)


def _fallback_rule_based_response(
    agent_input: ResponseInput
) -> ProposedAction:

    report = agent_input.diagnostic_report

    action_id = f"act_{report.timestamp}"
    if report.status == "ANOMALY":

        if (
            "battery" in (report.issue or "").lower()
            or "overheat" in (report.recommended_action or "").lower()
        ):

            return ProposedAction(
                action_id=action_id,
                run_id=report.run_id,
                action_type="ISOLATE_BATTERY",
                target="battery_1",
                reason=(
                    "Fallback: "
                    + (
                        report.issue
                        or "Battery issue detected."
                    )
                ),
                priority="HIGH",
                claimed_authorization=report.report_id
            )

        return ProposedAction(
            action_id=action_id,
            run_id=report.run_id,
            action_type="INVESTIGATE",
            target="unknown",
            reason="Fallback response for anomaly.",
            priority="MEDIUM",
            claimed_authorization=report.report_id
        )

    # Normal state

    return ProposedAction(
        action_id=action_id,
        run_id=report.run_id,
        action_type="MAINTAIN_STATUS",
        target="none",
        reason="System operating normally.",
        priority="LOW",
        claimed_authorization=report.report_id
    )


if __name__ == "__main__":

    print(
        "Testing Response Agent (requires Ollama running)..."
    )

    from agents.schemas import MonitoringReport

    report = MonitoringReport(
        report_id="rep_12:00",
        timestamp="12:00",
        status="ANOMALY",
        severity="HIGH",
        issue="Battery temperature reached 92C.",
        evidence={
            "battery_temperature_c": 92.0
        },
        recommended_action="Isolate battery immediately.",
        confidence=0.95
    )

    test_input = {
        "diagnostic_report": report.model_dump(),
        "current_state": {
            "battery_temperature_c": 92.0,
            "battery_soc_pct": 50.0
        }
    }

    proposal = run_response_agent(test_input)

    print("\n--- Proposed Action ---")
    print(proposal.model_dump_json(indent=2))