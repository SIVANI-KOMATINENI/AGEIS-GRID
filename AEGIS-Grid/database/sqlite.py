"""
database/sqlite.py
Manages the 4-table SQLite schema and provides insert/query helper functions.
"""

import sqlite3
import os
from pathlib import Path
from typing import List, Dict, Any

import config as cfg
from database.models import (
    ObservationRow, AgentMessageRow, AttackEventRow, AEGISDecisionRow
)

# Ensure the database directory exists
Path(cfg.SQLITE_PATH).parent.mkdir(parents=True, exist_ok=True)

SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
    obs_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT,
    timestamp TEXT,
    voltage_pu REAL,
    load_kw REAL,
    solar_kw REAL,
    battery_soc_pct REAL,
    battery_temperature_c REAL,
    transformer_loading_pct REAL
);

CREATE TABLE IF NOT EXISTS agent_messages (
    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT,
    timestamp TEXT,
    sender_agent TEXT,
    receiver_agent TEXT,
    message_content TEXT       -- JSON-serialized payload
);

CREATE TABLE IF NOT EXISTS attack_events (
    attack_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT,
    attack_type TEXT,
    target TEXT,
    start_time TEXT,
    end_time TEXT,
    ground_truth INTEGER        -- always 1 for real injected attacks
);

CREATE TABLE IF NOT EXISTS aegis_decisions (
    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT,
    timestamp TEXT,
    action_id TEXT,
    policy_result TEXT,
    provenance_result TEXT,
    behaviour_flag INTEGER,
    risk_score REAL,
    final_decision TEXT,        -- allow / block / human_approval
    reason TEXT,
    human_reviewer TEXT,        -- null if not escalated
    is_injected_attack INTEGER, -- ground truth, for evaluation only
    attack_type TEXT            -- ground truth, for evaluation only
);
"""

def init_db(db_path: str = cfg.SQLITE_PATH, wipe_existing: bool = False):
    """Initialises the database, optionally wiping existing data for a fresh run."""
    if wipe_existing and os.path.exists(db_path):
        os.remove(db_path)

    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(SCHEMA)
        for table in ("observations", "agent_messages", "attack_events", "aegis_decisions"):
            columns = {
                row[1]
                for row in conn.execute(f"PRAGMA table_info({table})")
            }
            if "run_id" not in columns:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN run_id TEXT")
        conn.commit()
    finally:
        conn.close()

def get_connection(db_path: str = cfg.SQLITE_PATH) -> sqlite3.Connection:
    return sqlite3.connect(db_path)

def insert_observation(obs: ObservationRow, db_path: str = cfg.SQLITE_PATH) -> int:
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO observations
            (run_id, timestamp, voltage_pu, load_kw, solar_kw, battery_soc_pct, battery_temperature_c, transformer_loading_pct)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            obs.run_id, obs.timestamp, obs.voltage_pu, obs.load_kw, obs.solar_kw,
            obs.battery_soc_pct, obs.battery_temperature_c, obs.transformer_loading_pct
        ))
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()

def insert_agent_message(msg: AgentMessageRow, db_path: str = cfg.SQLITE_PATH) -> int:
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO agent_messages (run_id, timestamp, sender_agent, receiver_agent, message_content)
            VALUES (?, ?, ?, ?, ?)
        ''', (msg.run_id, msg.timestamp, msg.sender_agent, msg.receiver_agent, msg.message_content))
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()

def insert_attack_event(event: AttackEventRow, db_path: str = cfg.SQLITE_PATH) -> int:
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO attack_events (run_id, attack_type, target, start_time, end_time, ground_truth)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (event.run_id, event.attack_type, event.target, event.start_time, event.end_time, event.ground_truth))
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()

def insert_aegis_decision(decision: AEGISDecisionRow, db_path: str = cfg.SQLITE_PATH) -> int:
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO aegis_decisions (
                run_id, timestamp, action_id, policy_result, provenance_result, behaviour_flag,
                risk_score, final_decision, reason, human_reviewer, is_injected_attack, attack_type
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            decision.run_id, decision.timestamp, decision.action_id, decision.policy_result,
            decision.provenance_result, decision.behaviour_flag, decision.risk_score,
            decision.final_decision, decision.reason, decision.human_reviewer,
            decision.is_injected_attack, decision.attack_type
        ))
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()

def query_recent_observations(n: int, db_path: str = cfg.SQLITE_PATH) -> List[Dict[str, Any]]:
    """Returns the `n` most recent observations in chronological order."""
    conn = sqlite3.connect(db_path)
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM observations ORDER BY obs_id DESC LIMIT ?
        ''', (n,))
        rows = cursor.fetchall()
        
        # Reverse to chronological order
        return [dict(row) for row in reversed(rows)]
    finally:
        conn.close()


def _query_recent_rows(
    table: str,
    id_column: str,
    n: int,
    db_path: str,
) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(db_path)
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT * FROM {table} ORDER BY {id_column} DESC LIMIT ?",
            (n,),
        )
        rows = cursor.fetchall()
        return [dict(row) for row in reversed(rows)]
    finally:
        conn.close()


def query_recent_agent_messages(
    n: int,
    db_path: str = cfg.SQLITE_PATH,
) -> List[Dict[str, Any]]:
    """Returns recent agent messages in insertion order."""
    return _query_recent_rows("agent_messages", "message_id", n, db_path)


def query_recent_attack_events(
    n: int,
    db_path: str = cfg.SQLITE_PATH,
) -> List[Dict[str, Any]]:
    """Returns recent attack events in insertion order."""
    return _query_recent_rows("attack_events", "attack_id", n, db_path)


def query_recent_decisions(
    n: int,
    db_path: str = cfg.SQLITE_PATH,
) -> List[Dict[str, Any]]:
    """Returns recent AEGIS decisions in insertion order."""
    return _query_recent_rows("aegis_decisions", "decision_id", n, db_path)
