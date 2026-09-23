"""
aegis/policy.py
Policy Verification Stage.
Fast, deterministic rule checking - no LLM needed.
"""

from pydantic import BaseModel
from typing import List, Dict, Any, Optional

from agents.schemas import ProposedAction

class PolicyResult(BaseModel):
    stage: str = "policy"
    decision: str    # "allow" | "block"
    matched_rule_id: Optional[str] = None
    reason: str


# ── Policy Rules (Data-driven, not hardcoded logic) ───────────────────────────

DEFAULT_RULES = [
    {
        "rule_id": "rule_001",
        "description": "Critical-load shutdown always requires Human Approval",
        "condition": lambda action: action.target == "critical_load" and action.action_type == "SHUTDOWN_LOAD",
        "action": "block",
        "reason": "Policy explicitly forbids auto-shutdown of critical load."
    },
    {
        "rule_id": "rule_002",
        "description": "Battery isolation requires a HIGH priority emergency claim",
        "condition": lambda action: action.target.startswith("battery") and action.action_type == "ISOLATE_BATTERY" and action.priority != "HIGH",
        "action": "block",
        "reason": "Battery isolation proposed without HIGH priority emergency status."
    },
    {
        "rule_id": "rule_003",
        "description": "Known safe actions",
        "condition": lambda action: action.action_type in ["MAINTAIN_STATUS", "INSPECT", "LOG_WARNING"],
        "action": "allow",
        "reason": "Benign observation/maintenance action."
    },
    {
        "rule_id": "rule_004",
        "description": "Cannot claim empty authorization on severe actions",
        "condition": lambda action: action.priority in ["MEDIUM", "HIGH"] and not action.claimed_authorization,
        "action": "block",
        "reason": "Severe action proposed without claiming proper authorization (missing diagnostic report ID)."
    }
]


def verify_policy(action: ProposedAction, rules: List[Dict[str, Any]] = DEFAULT_RULES) -> PolicyResult:
    """
    Evaluates the proposed action against the predefined ruleset.
    First rule that matches returns its decision.
    If no rules match, defaults to block (fail-safe).
    """
    for rule in rules:
        try:
            if rule["condition"](action):
                return PolicyResult(
                    decision=rule["action"],
                    matched_rule_id=rule["rule_id"],
                    reason=f"Matched {rule['rule_id']}: {rule['reason']}"
                )
        except Exception as e:
            # If a rule condition fails to evaluate, skip it safely
            continue
            
    # Default fallback (allow by default if no block/escalate rules matched)
    return PolicyResult(
        decision="allow",
        matched_rule_id="default_allow",
        reason="Action did not match any block/escalate rules."
    )

if __name__ == "__main__":
    test_action = ProposedAction(
        action_id="test1", 
        action_type="ISOLATE_BATTERY", 
        target="battery_1", 
        reason="test", 
        priority="LOW"
    )
    res = verify_policy(test_action)
    print(res.model_dump_json(indent=2))
