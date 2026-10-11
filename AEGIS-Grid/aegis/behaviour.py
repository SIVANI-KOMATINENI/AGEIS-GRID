"""
aegis/behaviour.py
Behaviour Analysis Stage.
Historical sliding window check to flag erratic agent behaviour.
Outputs a continuous anomaly score with deterministic security primacy.

AEGIS GRID Runtime Security Layer.
"""

import json
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from agents.schemas import ProposedAction
import config as cfg
from database.sqlite import query_recent_agent_messages


# ── Behaviour Anomaly Scoring Weights & Thresholds ────────────────────────────
# Rationale: All scoring contributions are explicit, documented, and bounded
# so cumulative penalties produce a calibrated score in [0.0, 1.0].

# Minimum history depth required before an agent is considered to have a reliable baseline.
# Rationale: 3 observations establish basic steady-state operating patterns.
MIN_BASELINE_DEPTH: int = 3

# Penalty when high-impact actions (ISOLATE_BATTERY, SHUTDOWN_LOAD) or HIGH priority
# are proposed without any baseline history.
# Rationale: Missing baseline cannot be treated as evidence of safety for disruptive actions.
SCORE_INSUFFICIENT_BASELINE_SEVERE: float = 0.40

# Penalty when severe actions are proposed with sparse baseline (1 or 2 actions).
# Rationale: Partial baseline reduces confidence when severe deviations occur.
SCORE_SPARSE_BASELINE_SEVERE: float = 0.25

# Novel action type penalty.
# Rationale: Action type unseen in sliding window indicates operational novelty.
SCORE_UNSEEN_ACTION: float = 0.30

# Priority escalation penalty.
# Rationale: Sudden jump to HIGH priority without prior MEDIUM warning indicates abnormal urgency.
SCORE_PRIORITY_ESCALATION: float = 0.40

# High-priority frequency burst penalty.
# Rationale: 3+ HIGH priority actions in sliding window indicates alarm storm or flooding.
SCORE_HIGH_PRIORITY_BURST: float = 0.50

# Repeated disruptive action penalty.
# Rationale: Repeated physical disconnections (ISOLATE_BATTERY, SHUTDOWN_LOAD) disrupt grid stability.
SCORE_REPEATED_DISRUPTIVE: float = 0.40

# Immediate consecutive disruptive action penalty.
# Rationale: Back-to-back disruptive commands without stabilization delay indicates control anomaly.
SCORE_CONSECUTIVE_DISRUPTIVE: float = 0.30

# Target concentration spam penalty.
# Rationale: Targeting a single component 4+ times in window indicates fixation or targeted disruption.
SCORE_TARGET_CONCENTRATION: float = 0.30

# Rapid target divergence penalty.
# Rationale: Rapidly hopping across 3+ distinct components indicates lateral scanning or scatter disruption.
SCORE_RAPID_TARGET_PIVOT: float = 0.25

# Unusual sequence: steady state (MAINTAIN_STATUS) directly to emergency disconnection.
# Rationale: Normal operational protocols require progressive diagnosis before severe disconnection.
SCORE_UNUSUAL_SEQUENCE: float = 0.35

# Priority flip-flop penalty.
# Rationale: Wild oscillations between LOW and HIGH priority indicate sensor flapping or erratic control.
SCORE_PRIORITY_FLIP_FLOP: float = 0.20

# Threshold above which an action is considered an anomaly.
# Actions scoring at or above this threshold are quarantined and not automatically added to trusted baseline.
ANOMALY_QUARANTINE_THRESHOLD: float = 0.30


class BehaviourResult(BaseModel):
    stage: str = "behaviour"
    flagged: bool
    score: float = 0.0  # 0.0 to 1.0 based on severity/count of flags
    deviation_reason: Optional[str] = None
    anomaly_types: List[str] = Field(default_factory=list)
    history_length: int = 0
    quarantined: bool = False
    deterministic_score: float = 0.0
    llm_adjusted: bool = False


# State dictionary holding typical recent behaviour (trusted baseline)
# Format: { "agent_name": [action1, action2, ... ] }
_recent_history: Dict[str, List[ProposedAction]] = {}

# Quarantined anomalous actions (isolated from trusted baseline)
_quarantined_history: Dict[str, List[ProposedAction]] = {}

_db_load_enabled: bool = True
_db_path_override: Optional[str] = None


def reset_behaviour_history(
    enable_db_load: bool = False,
    db_path: Optional[str] = None,
):
    """
    Clear in-memory behaviour history and quarantined actions.
    
    Args:
        enable_db_load: Defaults to False so calling reset_behaviour_history() in unit
            tests prevents cross-test contamination from SQLite. Pass True to re-enable
            DB loading or use load_behaviour_history_from_db().
        db_path: Optional SQLite database path override (e.g. for isolated test databases).
    """
    global _recent_history, _quarantined_history, _db_load_enabled, _db_path_override
    _recent_history = {}
    _quarantined_history = {}
    _db_load_enabled = enable_db_load
    _db_path_override = db_path


def set_db_load_enabled(enabled: bool):
    """Enable or disable database history loading."""
    global _db_load_enabled
    _db_load_enabled = enabled


def record_trusted_action(action: ProposedAction) -> None:
    """
    Explicitly adds an approved/verified action into the trusted baseline history.
    Used when an action has passed AEGIS controller authorization and actuation.
    """
    agent = action.sender_agent or "response_agent"
    if agent not in _recent_history:
        _recent_history[agent] = []
    _recent_history[agent].append(action)
    if len(_recent_history[agent]) > cfg.BEHAVIOUR_HISTORY_SIZE:
        _recent_history[agent].pop(0)


def discard_untrusted_action(action_id: str, agent: Optional[str] = None) -> bool:
    """
    Purges an action from the trusted baseline if it was rejected/blocked downstream
    (e.g. by policy, provenance, replay detection, or human reviewer).
    Returns True if an action was removed, False otherwise.
    """
    global _recent_history
    removed = False
    agents_to_check = [agent] if agent else list(_recent_history.keys())
    for a in agents_to_check:
        if a in _recent_history:
            original_len = len(_recent_history[a])
            _recent_history[a] = [act for act in _recent_history[a] if act.action_id != action_id]
            if len(_recent_history[a]) < original_len:
                removed = True
    return removed


def quarantine_action(action: ProposedAction, reason: Optional[str] = None) -> None:
    """
    Moves or records an action directly into the quarantined anomalous history,
    ensuring it is purged from the trusted baseline.
    """
    agent = action.sender_agent or "response_agent"
    discard_untrusted_action(action.action_id, agent=agent)
    if agent not in _quarantined_history:
        _quarantined_history[agent] = []
    _quarantined_history[agent].append(action)
    if len(_quarantined_history[agent]) > cfg.BEHAVIOUR_HISTORY_SIZE:
        _quarantined_history[agent].pop(0)


def get_recent_history(agent: str) -> List[ProposedAction]:
    """Returns a copy of the trusted baseline history for the given agent."""
    return list(_recent_history.get(agent, []))


def get_quarantined_history(agent: str) -> List[ProposedAction]:
    """Returns a copy of quarantined anomalous actions for the given agent."""
    return list(_quarantined_history.get(agent, []))


def load_behaviour_history_from_db(
    agent: Optional[str] = None,
    db_path: Optional[str] = None,
) -> int:
    """
    Explicitly loads persisted behaviour history from SQLite into memory.
    Filters out any actions whose decisions were BLOCKED or suspicious.
    Re-enables DB loading if it was previously disabled.
    Returns the count of loaded actions.
    """
    global _db_load_enabled, _db_path_override
    _db_load_enabled = True
    if db_path is not None:
        _db_path_override = db_path
    target_path = db_path or _db_path_override or cfg.SQLITE_PATH
    
    if agent:
        if agent in _recent_history:
            del _recent_history[agent]
        _load_history_from_db(agent, db_path=target_path)
        return len(_recent_history.get(agent, []))
    else:
        try:
            messages = query_recent_agent_messages(50, db_path=target_path)
            agents = {m["sender_agent"] for m in messages if m.get("sender_agent")}
            total = 0
            for a in agents:
                if a in _recent_history:
                    del _recent_history[a]
                _load_history_from_db(a, db_path=target_path)
                total += len(_recent_history.get(a, []))
            return total
        except Exception:
            return 0


def _load_history_from_db(agent: str, db_path: Optional[str] = None):
    """
    Loads the last N unblocked actions for this agent from SQLite into memory.
    Cross-references decision logs to prevent blocked/suspicious actions from contaminating baseline.
    Does NOT use ground-truth attack labels.
    """
    if agent in _recent_history:
        return
        
    _recent_history[agent] = []
    if not _db_load_enabled:
        return
    
    target_path = db_path or _db_path_override or cfg.SQLITE_PATH

    # Identify blocked or suspicious actions from decisions to prevent baseline poisoning
    # Uses only runtime security outcomes (final_decision, behaviour_flag), NEVER ground-truth attack labels
    blocked_action_ids = set()
    try:
        from database.sqlite import query_recent_decisions
        decisions = query_recent_decisions(200, db_path=target_path)
        for dec in decisions:
            if dec.get("final_decision") != "allow" or dec.get("behaviour_flag", 0) == 1:
                action_id = dec.get("action_id")
                if action_id:
                    blocked_action_ids.add(action_id)
    except Exception:
        pass

    # Query recent messages and load only trusted/unblocked actions
    try:
        messages = query_recent_agent_messages(100, db_path=target_path)
        for msg in messages:
            if msg.get("sender_agent") == agent:
                try:
                    action_data = json.loads(msg["message_content"])
                    action = ProposedAction(**action_data)
                    # Filter out blocked/attacked actions from trusted baseline
                    if action.action_id in blocked_action_ids:
                        continue
                    _recent_history[agent].append(action)
                except Exception:
                    pass
    except Exception:
        pass
        
    # Keep only the most recent N
    _recent_history[agent] = _recent_history[agent][-cfg.BEHAVIOUR_HISTORY_SIZE:]


def analyze_behaviour(
    action: ProposedAction,
    llm_analysis: Optional[Dict[str, Any]] = None,
    auto_record: bool = True,
) -> BehaviourResult:
    """
    Analyzes action against recent history and produces a continuous anomaly score.
    Enforces deterministic security primacy over any optional LLM guidance.

    Checks for:
    - Insufficient baseline history on severe actions (anti-cold-start bypass)
    - Unseen action types
    - Sudden priority jumps
    - High-priority action bursts
    - Repeated high-impact disruptive actions (ISOLATE_BATTERY, SHUTDOWN_LOAD)
    - Immediate consecutive disruptive actions
    - Target concentration spamming
    - Rapid target divergence (lateral scanning/hopping)
    - Unusual action sequences (steady state directly to emergency disconnection)
    - Priority flip-flop oscillations
    """
    agent = action.sender_agent or "response_agent"
    
    # Pre-load from DB if not already loaded
    _load_history_from_db(agent)
        
    history = _recent_history.get(agent, [])
    history_len = len(history)
    
    # ── 1. Empty Baseline History Check ──────────────────────────────────────
    if not history:
        is_severe = (
            action.action_type in ("ISOLATE_BATTERY", "SHUTDOWN_LOAD")
            or action.priority == "HIGH"
        )
        if is_severe:
            # Do NOT treat missing history as proof that severe behaviour is safe!
            reason = (
                f"Insufficient baseline history: High-impact action '{action.action_type}' "
                f"with priority '{action.priority}' proposed without established operational baseline."
            )
            if auto_record:
                if agent not in _quarantined_history:
                    _quarantined_history[agent] = []
                _quarantined_history[agent].append(action)
            return BehaviourResult(
                flagged=True,
                score=SCORE_INSUFFICIENT_BASELINE_SEVERE,
                deviation_reason=reason,
                anomaly_types=["insufficient_baseline_severe"],
                history_length=0,
                quarantined=True,
                deterministic_score=SCORE_INSUFFICIENT_BASELINE_SEVERE,
            )
        else:
            # Routine action accepted as initial baseline
            if auto_record:
                if agent not in _recent_history:
                    _recent_history[agent] = []
                _recent_history[agent].append(action)
            return BehaviourResult(
                flagged=False,
                score=0.0,
                deviation_reason="No baseline history yet; routine action accepted as initial baseline.",
                anomaly_types=[],
                history_length=0,
                quarantined=False,
                deterministic_score=0.0,
            )

    past_types = set([a.action_type for a in history])
    past_priorities = set([a.priority for a in history])
    
    reasons = []
    anomaly_types = []
    score = 0.0

    # ── 2. Sparse Baseline Check (< MIN_BASELINE_DEPTH) ───────────────────────
    if history_len < MIN_BASELINE_DEPTH:
        if action.priority == "HIGH" or action.action_type in ("ISOLATE_BATTERY", "SHUTDOWN_LOAD"):
            reasons.append(
                f"Sparse baseline history: High-impact action proposed before baseline reached "
                f"minimum depth ({history_len}/{MIN_BASELINE_DEPTH})."
            )
            anomaly_types.append("sparse_baseline_severe")
            score += SCORE_SPARSE_BASELINE_SEVERE

    # ── 3. Novel Action Type Check ───────────────────────────────────────────
    if action.action_type not in past_types:
        reasons.append(f"Action '{action.action_type}' never seen in recent history.")
        anomaly_types.append("unseen_action_type")
        score += SCORE_UNSEEN_ACTION
        
    # ── 4. Priority Escalation Check ─────────────────────────────────────────
    if action.priority == "HIGH" and "HIGH" not in past_priorities and "MEDIUM" not in past_priorities:
        reasons.append("Sudden escalation to HIGH priority without prior MEDIUM warnings.")
        anomaly_types.append("priority_escalation")
        score += SCORE_PRIORITY_ESCALATION
        
    # ── 5. High-Priority Burst Check ─────────────────────────────────────────
    if action.priority == "HIGH":
        high_count = sum(1 for a in history if a.priority == "HIGH")
        if high_count >= 2:
            reasons.append(f"Frequency anomaly: {high_count + 1} HIGH priority actions in recent window.")
            anomaly_types.append("high_priority_burst")
            score += SCORE_HIGH_PRIORITY_BURST

    # ── 6. Repeated Disruptive Actions Check ─────────────────────────────────
    if action.action_type in ("ISOLATE_BATTERY", "SHUTDOWN_LOAD"):
        prior_disruptive = sum(
            1 for a in history if a.action_type in ("ISOLATE_BATTERY", "SHUTDOWN_LOAD")
        )
        quarantined_disruptive = sum(
            1 for a in _quarantined_history.get(agent, [])
            if a.action_type in ("ISOLATE_BATTERY", "SHUTDOWN_LOAD")
        )
        total_disruptive = prior_disruptive + quarantined_disruptive
        if total_disruptive >= 1:
            reasons.append(
                f"Repeated disruptive actions: {total_disruptive} prior disruptive action(s) detected in window."
            )
            anomaly_types.append("repeated_disruptive_actions")
            score += SCORE_REPEATED_DISRUPTIVE

    # ── 7. Immediate Consecutive Disruptive Action ────────────────────────────
    if (
        history_len >= 1
        and history[-1].action_type == action.action_type
        and action.action_type in ("ISOLATE_BATTERY", "SHUTDOWN_LOAD")
    ):
        reasons.append(
            f"Consecutive high-impact repetition: Action '{action.action_type}' repeated immediately back-to-back."
        )
        anomaly_types.append("consecutive_disruptive_action")
        score += SCORE_CONSECUTIVE_DISRUPTIVE
            
    # ── 8. Target Concentration Spam Check ───────────────────────────────────
    target_count = sum(1 for a in history if a.target == action.target and action.target not in ("none", "unknown"))
    if target_count >= 3:
        reasons.append(f"Target concentration: Component {action.target} targeted {target_count + 1} times recently.")
        anomaly_types.append("target_concentration")
        score += SCORE_TARGET_CONCENTRATION

    # ── 9. Rapid Target Divergence / Lateral Hopping ─────────────────────────
    if history_len >= 2 and action.target not in ("none", "unknown"):
        recent_targets = [a.target for a in history[-2:] if a.target not in ("none", "unknown")]
        if (
            len(recent_targets) == 2
            and len(set(recent_targets)) == 2
            and action.target not in recent_targets
        ):
            reasons.append(
                f"Rapid target divergence: Agent pivoting across distinct targets "
                f"({list(set(recent_targets))} -> {action.target}) in rapid succession."
            )
            anomaly_types.append("rapid_target_divergence")
            score += SCORE_RAPID_TARGET_PIVOT

    # ── 10. Unusual Sequence (Steady State -> Abrupt Emergency Disconnect) ────
    if action.action_type in ("ISOLATE_BATTERY", "SHUTDOWN_LOAD") and action.priority == "HIGH":
        if history_len >= 2 and all(a.action_type == "MAINTAIN_STATUS" for a in history[-2:]):
            reasons.append(
                "Unusual sequence: Abrupt jump from steady-state MAINTAIN_STATUS directly to "
                "emergency disconnection without preceding investigation or warning."
            )
            anomaly_types.append("unusual_sequence_abrupt_disconnect")
            score += SCORE_UNUSUAL_SEQUENCE
         
    # ── 11. Priority Flip-Flop Check ─────────────────────────────────────────
    if history_len >= 2:
        last_pri = history[-1].priority
        prev_pri = history[-2].priority
        if (last_pri == "LOW" and action.priority == "HIGH") or (last_pri == "HIGH" and action.priority == "LOW"):
            if prev_pri == action.priority:
                reasons.append("Flip-flop behaviour detected in priority levels.")
                anomaly_types.append("priority_flip_flop")
                score += SCORE_PRIORITY_FLIP_FLOP

    deterministic_score = min(1.0, round(score, 3))
    final_score = deterministic_score
    llm_adjusted = False

    # ── 12. Deterministic Primacy Over Optional LLM Output ───────────────────
    if llm_analysis is not None:
        try:
            llm_val = float(
                llm_analysis.get("score", 0.0)
                if isinstance(llm_analysis, dict)
                else getattr(llm_analysis, "score", 0.0)
            )
            # Security Rule: LLM can only elevate the score; it CANNOT suppress or lower deterministic score!
            if llm_val > deterministic_score:
                final_score = llm_val
                llm_adjusted = True
                llm_reason = (
                    llm_analysis.get("reason", "LLM identified behavioural anomaly")
                    if isinstance(llm_analysis, dict)
                    else getattr(llm_analysis, "reason", "LLM identified behavioural anomaly")
                )
                reasons.append(f"LLM elevated anomaly: {llm_reason}")
                anomaly_types.append("llm_anomaly")
        except (ValueError, TypeError):
            pass

    final_score = min(1.0, max(0.0, round(final_score, 3)))
    flagged = final_score > 0.0

    # ── 13. Quarantine & Anti-Poisoning Memory Update ────────────────────────
    is_anomalous = final_score >= ANOMALY_QUARANTINE_THRESHOLD or deterministic_score >= ANOMALY_QUARANTINE_THRESHOLD
    quarantined = is_anomalous

    if auto_record:
        if is_anomalous:
            # Quarantine anomalous action to prevent baseline poisoning
            if agent not in _quarantined_history:
                _quarantined_history[agent] = []
            _quarantined_history[agent].append(action)
            if len(_quarantined_history[agent]) > cfg.BEHAVIOUR_HISTORY_SIZE:
                _quarantined_history[agent].pop(0)
        else:
            # Routine / baseline-compliant action joins trusted baseline
            if agent not in _recent_history:
                _recent_history[agent] = []
            _recent_history[agent].append(action)
            if len(_recent_history[agent]) > cfg.BEHAVIOUR_HISTORY_SIZE:
                _recent_history[agent].pop(0)

    return BehaviourResult(
        flagged=flagged,
        score=final_score,
        deviation_reason=" | ".join(reasons) if flagged else None,
        anomaly_types=anomaly_types,
        history_length=history_len,
        quarantined=quarantined,
        deterministic_score=deterministic_score,
        llm_adjusted=llm_adjusted,
    )


if __name__ == "__main__":
    act1 = ProposedAction(action_id="1", action_type="MAINTAIN_STATUS", target="none", reason="test", priority="LOW")
    act2 = ProposedAction(action_id="2", action_type="ISOLATE_BATTERY", target="battery_1", reason="test", priority="HIGH")
    
    print("Action 1:", analyze_behaviour(act1))
    print("Action 2:", analyze_behaviour(act2))
