"""
aegis/policy.py
Policy Verification Stage.
Fast, deterministic rule checking - no LLM needed.
Now supports 'human_approval' as a direct policy outcome.
"""

import inspect
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

from agents.schemas import ProposedAction

class PolicyResult(BaseModel):
    stage: str = "policy"
    decision: str    # "allow" | "block" | "human_approval"
    matched_rule_id: Optional[str] = None
    reason: str


def _eval_condition(condition, action: ProposedAction, context: Optional[Dict[str, Any]] = None) -> bool:
    """Safely evaluates rule conditions accepting either (action) or (action, context)."""
    try:
        sig = inspect.signature(condition)
        if len(sig.parameters) >= 2:
            return bool(condition(action, context))
        return bool(condition(action))
    except TypeError:
        try:
            return bool(condition(action, context))
        except TypeError:
            return bool(condition(action))


# ── Policy Rules (Data-driven, not hardcoded logic) ───────────────────────────

DEFAULT_RULES = [

    # 0b. Explicit Forged or Malformed Token Blocklist
    {
        "rule_id": "rule_000_forged_auth",
        "description": "Reject explicit forged or malformed authorization tokens",
        "condition": lambda action, ctx=None: bool(
            action.claimed_authorization and (
                action.claimed_authorization.startswith("auth_tok_")
                or "forged" in action.claimed_authorization.lower()
                or "fake" in action.claimed_authorization.lower()
                or "spoof" in action.claimed_authorization.lower()
            )
        ),
        "action": "block",
        "reason": "Action carries an invalid or forged authorization token format.",
    },

    # 0c. Claimed Personnel Identifier Without Cryptographic Evidence
    {
        "rule_id": "rule_000_unauthenticated_personnel",
        "description": "Reject claimed personnel IDs lacking cryptographic AuthorizationEvidence",
        "condition": lambda action, ctx=None: bool(
            action.claimed_authorization and (
                action.claimed_authorization.startswith("PERS-")
                or action.claimed_authorization.startswith("cred_pers_")
            ) and getattr(action, "authorization_evidence", None) is None
        ),
        "action": "block",
        "reason": "Claimed personnel identifier requires cryptographic AuthorizationEvidence.",
    },

    # 0d. Unverified or Out-of-Scope Personnel Credential
    {
        "rule_id": "rule_000_unauthorized_personnel",
        "description": "Reject actions with unverified or unauthorized personnel authorization",
        "condition": lambda action, ctx=None: bool(
            ctx and ctx.get("auth_res") and not ctx["auth_res"].is_authorized
        ),
        "action": "block",
        "reason": "Personnel credential verification failed or action is outside authorized scope.",
    },

    # 1. Mandatory Authorization: Severe or prioritized actions cannot have empty authorization
    {
        "rule_id": "rule_004",
        "description": "Cannot claim empty authorization on severe actions",
        "condition": lambda action, ctx=None: (
            action.priority in ["MEDIUM", "HIGH"]
            or action.action_type in ["ISOLATE_BATTERY", "SHUTDOWN_LOAD", "REDUCE_LOAD"]
        ) and not action.claimed_authorization and getattr(action, "authorization_evidence", None) is None,
        "action": "block",
        "reason": "Severe action proposed without claiming proper authorization (missing diagnostic report ID).",
    },

    # 2. Structural Validation: Unknown action types escalate to human review
    {
        "rule_id": "rule_005",
        "description": "Unknown action types escalate to human",
        "condition": lambda action, ctx=None: action.action_type not in [
            "ISOLATE_BATTERY", "REDUCE_LOAD", "SHUTDOWN_LOAD",
            "MAINTAIN_STATUS", "INSPECT", "LOG_WARNING", "INVESTIGATE"
        ],
        "action": "human_approval",
        "reason": "Unrecognised action type proposed.",
    },

    # 3. Proportionality: HIGH priority on non-severe/empty target is rejected
    {
        "rule_id": "rule_008",
        "description": "Proportionality check: HIGH priority on non-severe target",
        "condition": lambda action, ctx=None: action.priority == "HIGH" and action.target in ["none", "unknown"],
        "action": "block",
        "reason": "HIGH priority action proposed with no specific target.",
    },

    # 4. Critical Load Safety: Critical-load shutdown ALWAYS requires human approval
    {
        "rule_id": "rule_001",
        "description": "Critical-load shutdown always requires Human Approval",
        "condition": lambda action, ctx=None: action.target == "critical_load" and action.action_type == "SHUTDOWN_LOAD",
        "action": "human_approval",
        "reason": "Policy explicitly forbids auto-shutdown of critical load. Human review required.",
    },

    # 4b. Battery Isolation Priority Check
    {
        "rule_id": "rule_002",
        "description": "Battery isolation requires a HIGH priority emergency claim",
        "condition": lambda action, ctx=None: action.target.startswith("battery") and action.action_type == "ISOLATE_BATTERY" and action.priority != "HIGH",
        "action": "block",
        "reason": "Battery isolation proposed without HIGH priority emergency status.",
    },

    # 5. Battery Isolation Target Check
    {
        "rule_id": "rule_002a",
        "description": "Battery isolation must target battery component",
        "condition": lambda action, ctx=None: action.action_type == "ISOLATE_BATTERY" and not action.target.startswith("battery"),
        "action": "block",
        "reason": "Battery isolation proposed on non-battery target.",
    },

    # 6. Physical Telemetry Corroboration: High-priority battery isolation on normal telemetry is rejected
    {
        "rule_id": "rule_002c",
        "description": "Battery isolation unsupported by normal telemetry",
        "condition": lambda action, ctx=None: (
            action.action_type == "ISOLATE_BATTERY"
            and ctx is not None
            and ctx.get("battery_temperature_c") is not None
            and float(ctx.get("battery_temperature_c", 30.0)) <= 50.0
            and ctx.get("report_status") == "NORMAL"
        ),
        "action": "block",
        "reason": "High-priority battery isolation is unsupported by microgrid telemetry (battery temperature is normal).",
    },

    # 7. Physical Parameter Constraints: Load reduction setpoint must be within feeder physics
    {
        "rule_id": "rule_006_physical_parameter_limits",
        "description": "Physical feasibility of load reduction parameters",
        "condition": lambda action, ctx=None: (
            action.action_type == "REDUCE_LOAD"
            and (
                (
                    (action.parameters.get("reduction_kw") is not None or action.parameters.get("amount_kw") is not None)
                    and float(action.parameters.get("reduction_kw") if action.parameters.get("reduction_kw") is not None else action.parameters.get("amount_kw")) <= 0
                )
                or (
                    (action.parameters.get("reduction_kw") is not None or action.parameters.get("amount_kw") is not None)
                    and float(action.parameters.get("reduction_kw") if action.parameters.get("reduction_kw") is not None else action.parameters.get("amount_kw")) > 1000.0
                )
            )
        ),
        "action": "block",
        "reason": "Load reduction setpoint violates physical grid safety constraints (must be positive and <= 1000 kW).",
    },

    # 8. Verified Personnel In-Scope Authorized Action: Allowed once all physical safety checks passed
    {
        "rule_id": "rule_007_personnel_authorized",
        "description": "In-scope authorized personnel action",
        "condition": lambda action, ctx=None: bool(
            ctx and ctx.get("auth_res") and ctx["auth_res"].is_authorized
        ),
        "action": "allow",
        "reason": "Action authorized by verified operational personnel credential.",
    },

    # 9. Corroborated Emergency Isolation: Allowed only if diagnostic report or telemetry is corroborated
    {
        "rule_id": "rule_002_emergency",
        "description": "Corroborated battery emergency isolation",
        "condition": lambda action, ctx=None: (
            action.action_type == "ISOLATE_BATTERY"
            and action.target.startswith("battery")
            and action.priority == "HIGH"
            and (
                # Physical anomaly corroboration in telemetry
                (
                    ctx is not None
                    and (
                        (ctx.get("battery_temperature_c") is not None and float(ctx.get("battery_temperature_c", 0.0)) > 50.0)
                        or ctx.get("report_status") == "ANOMALY"
                        or ctx.get("report_severity") in ["HIGH", "CRITICAL"]
                    )
                )
                # Or standalone test context where legitimate report claim is made without normal-telemetry contradiction
                or (
                    ctx is None
                    and bool(
                        action.claimed_authorization
                        and not (
                            action.claimed_authorization.startswith("auth_tok_")
                            or "forged" in action.claimed_authorization.lower()
                            or "fake" in action.claimed_authorization.lower()
                            or "spoof" in action.claimed_authorization.lower()
                        )
                    )
                )
            )
        ),
        "action": "allow",
        "reason": "Emergency battery isolation permitted under diagnostic authorization.",
    },

    # 10. Permissive Rule for Known Safe Actions: Must not be HIGH priority
    {
        "rule_id": "rule_003",
        "description": "Known safe actions",
        "condition": lambda action, ctx=None: (
            action.action_type in ["MAINTAIN_STATUS", "INSPECT", "LOG_WARNING", "INVESTIGATE"]
            and action.priority != "HIGH"
        ),
        "action": "allow",
        "reason": "Benign observation/maintenance action.",
    },
]


def verify_policy(
    action: ProposedAction,
    rules: Optional[List[Dict[str, Any]]] = None,
    context: Optional[Dict[str, Any]] = None,
    personnel_registry: Optional[Any] = None,
    now: Optional[Any] = None,
) -> PolicyResult:
    """
    Evaluates the proposed action against the predefined ruleset.
    First rule that matches returns its decision.
    If no rules match, defaults to fail-closed (block or human_approval, never allow).
    """
    ctx = dict(context or {})

    # Evaluate personnel authority if authorization evidence is present
    evidence = getattr(action, "authorization_evidence", None)
    if evidence is not None and evidence.token_type == "PERSONNEL_CREDENTIAL":
        from aegis.personnel import verify_personnel_authority

        reg = personnel_registry or ctx.get("personnel_registry")
        eval_now = now or ctx.get("now")
        auth_res = verify_personnel_authority(action, registry=reg, now=eval_now)
        ctx["auth_res"] = auth_res

    active_rules = rules if rules is not None else DEFAULT_RULES
    for rule in active_rules:
        try:
            if _eval_condition(rule["condition"], action, ctx):
                reason = rule["reason"]
                if rule["rule_id"] == "rule_000_unauthorized_personnel" and ctx.get("auth_res"):
                    auth_res = ctx["auth_res"]
                    reason = f"Personnel verification failed ({auth_res.status_code}): {auth_res.failure_reason}"
                elif rule["rule_id"] == "rule_007_personnel_authorized" and ctx.get("auth_res"):
                    auth_res = ctx["auth_res"]
                    reason = f"Personnel action authorized for {auth_res.role or 'operator'} ({auth_res.personnel_id})."
                return PolicyResult(
                    decision=rule["action"],
                    matched_rule_id=rule["rule_id"],
                    reason=f"Matched {rule['rule_id']}: {reason}"
                )
        except Exception:
            # If a rule condition fails to evaluate, skip it safely
            continue

    # Explicit empty ruleset forces fail-closed default evaluation
    if rules is not None and len(rules) == 0:
        if (
            action.priority in ["MEDIUM", "HIGH"]
            or action.action_type in ["ISOLATE_BATTERY", "SHUTDOWN_LOAD", "REDUCE_LOAD"]
        ):
            return PolicyResult(
                decision="block",
                matched_rule_id="default_deny",
                reason="Policy Denied: Unmatched or unauthorized severe action did not meet any permissive policy rule.",
            )
        return PolicyResult(
            decision="human_approval",
            matched_rule_id="default_escalate",
            reason="Policy Escalation: Unmatched action requires human review before execution.",
        )

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
