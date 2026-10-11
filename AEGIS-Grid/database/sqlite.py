"""
database/sqlite.py
Manages the 4-table SQLite schema and provides insert/query helper functions.
"""

import hashlib
import json
import sqlite3
import os
from pathlib import Path
from datetime import datetime, time
from typing import List, Dict, Any, Optional

import config as cfg
from database.models import (
    ObservationRow,
    AgentMessageRow,
    AttackEventRow,
    AEGISDecisionRow,
    ReplayCheckResult,
)

FINGERPRINT_FIELDS = (
    "timestamp",
    "voltage_pu",
    "load_kw",
    "solar_kw",
    "battery_soc_pct",
    "battery_temperature_c",
    "transformer_loading_pct",
)

# Ensure the database directory exists
Path(cfg.SQLITE_PATH).parent.mkdir(parents=True, exist_ok=True)

SCHEMA = """
CREATE TABLE IF NOT EXISTS simulation_sessions (
    session_id TEXT PRIMARY KEY,
    start_time TEXT,
    created_at TEXT,
    description TEXT
);

CREATE TABLE IF NOT EXISTS observations (
    obs_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT,
    session_id TEXT,
    execution_timestamp TEXT,
    fingerprint TEXT,
    replay_detected INTEGER NOT NULL DEFAULT 0,
    replay_reason TEXT,
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
    session_id TEXT,
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

CREATE TABLE IF NOT EXISTS report_consumptions (
    consumption_id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    status TEXT NOT NULL,        -- 'CONSUMED'
    action_digest TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_report_session_consumed 
ON report_consumptions (report_id, session_id) 
WHERE status = 'CONSUMED';

CREATE TABLE IF NOT EXISTS personnel_credential_consumptions (
    consumption_id INTEGER PRIMARY KEY AUTOINCREMENT,
    personnel_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    action_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'CONSUMED',
    action_digest TEXT NOT NULL,
    co_signer_id TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_personnel_credential_consumed
ON personnel_credential_consumptions (personnel_id, nonce)
WHERE status = 'CONSUMED';

CREATE TABLE IF NOT EXISTS neo4j_outbox (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    action_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    retry_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_outbox_status ON neo4j_outbox(status);
"""

DEFAULT_SESSION_ID = "default_session"
_active_session_id: str | None = None


def get_active_session_id() -> str:
    """Returns the currently active simulation/session boundary."""
    global _active_session_id
    if _active_session_id is None:
        return DEFAULT_SESSION_ID
    return _active_session_id


def set_active_session_id(session_id: str | None) -> str:
    """Sets the active simulation/session boundary."""
    global _active_session_id
    _active_session_id = session_id
    return _active_session_id or DEFAULT_SESSION_ID


def start_simulation_session(
    session_id: str | None = None,
    description: str | None = None,
    db_path: str = cfg.SQLITE_PATH,
) -> str:
    """
    Explicitly starts a new persistent simulation session boundary.
    Any observations recorded under this session will be scoped to this session.
    """
    actual_session_id = session_id or f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    set_active_session_id(actual_session_id)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT OR REPLACE INTO simulation_sessions (session_id, start_time, created_at, description)
               VALUES (?, ?, ?, ?)""",
            (
                actual_session_id,
                datetime.now().isoformat(),
                datetime.now().isoformat(),
                description or "Simulation session",
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return actual_session_id


def init_db(db_path: str = cfg.SQLITE_PATH, wipe_existing: bool = False):
    """Initialises the database, optionally wiping existing data for a fresh run."""
    if wipe_existing and os.path.exists(db_path):
        os.remove(db_path)

    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(SCHEMA)
        for table in ("observations", "agent_messages", "attack_events", "aegis_decisions", "report_consumptions", "personnel_credential_consumptions"):
            columns = {
                row[1]
                for row in conn.execute(f"PRAGMA table_info({table})")
            }
            if "run_id" not in columns:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN run_id TEXT")
            if table == "observations":
                if "session_id" not in columns:
                    conn.execute("ALTER TABLE observations ADD COLUMN session_id TEXT")
                if "execution_timestamp" not in columns:
                    conn.execute("ALTER TABLE observations ADD COLUMN execution_timestamp TEXT")
                if "fingerprint" not in columns:
                    conn.execute("ALTER TABLE observations ADD COLUMN fingerprint TEXT")
                if "replay_detected" not in columns:
                    conn.execute("ALTER TABLE observations ADD COLUMN replay_detected INTEGER NOT NULL DEFAULT 0")
                if "replay_reason" not in columns:
                    conn.execute("ALTER TABLE observations ADD COLUMN replay_reason TEXT")
            if table == "aegis_decisions":
                if "session_id" not in columns:
                    conn.execute("ALTER TABLE aegis_decisions ADD COLUMN session_id TEXT")
            if table == "report_consumptions":
                if "action_digest" not in columns:
                    conn.execute("ALTER TABLE report_consumptions ADD COLUMN action_digest TEXT")
        conn.commit()
    finally:
        conn.close()

def get_connection(db_path: str = cfg.SQLITE_PATH) -> sqlite3.Connection:
    return sqlite3.connect(db_path)


def observation_fingerprint(observation: Dict[str, Any]) -> str:
    """Generate deterministic SHA-256 fingerprint for observation telemetry."""
    payload = {field: observation[field] for field in FINGERPRINT_FIELDS}
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _timestamp_order_key(timestamp: str):
    try:
        parsed_datetime = datetime.fromisoformat(timestamp)
        return ("datetime", parsed_datetime.timestamp())
    except ValueError:
        try:
            parsed_time = time.fromisoformat(timestamp)
        except ValueError:
            return None
        seconds = (
            parsed_time.hour * 3600
            + parsed_time.minute * 60
            + parsed_time.second
            + parsed_time.microsecond / 1_000_000
        )
        return ("time", seconds)


def check_observation_replay(
    observation: Dict[str, Any],
    db_path: str = cfg.SQLITE_PATH,
    execution_timestamp: str | None = None,
    session_id: str | None = None,
) -> ReplayCheckResult:
    """Detect a previously seen telemetry fingerprint or regressing timestamp within the session boundary."""
    fingerprint = observation_fingerprint(observation)
    conn = sqlite3.connect(db_path)
    try:
        return _check_observation_replay_in_connection(
            conn,
            observation,
            fingerprint,
            execution_timestamp,
            session_id,
        )
    finally:
        conn.close()


def _check_observation_replay_in_connection(
    conn: sqlite3.Connection,
    observation: Dict[str, Any],
    fingerprint: str,
    execution_timestamp: str | None = None,
    session_id: str | None = None,
) -> ReplayCheckResult:
    target_session_id = (
        session_id
        or observation.get("session_id")
        or get_active_session_id()
    )

    duplicate = conn.execute(
        """SELECT 1 FROM observations
           WHERE fingerprint = ? AND COALESCE(session_id, 'default_session') = ?
           LIMIT 1""",
        (fingerprint, target_session_id),
    ).fetchone()

    latest = conn.execute(
        """SELECT timestamp, execution_timestamp FROM observations
           WHERE COALESCE(replay_detected, 0) = 0
             AND COALESCE(session_id, 'default_session') = ?
           ORDER BY obs_id DESC LIMIT 1""",
        (target_session_id,),
    ).fetchone()

    if duplicate:
        return ReplayCheckResult(
            detected=True,
            reason="Duplicate observation fingerprint has already been recorded in this session.",
            fingerprint=fingerprint,
            observation_timestamp=str(observation["timestamp"]),
            run_id=observation.get("run_id"),
            session_id=target_session_id,
        )

    incoming_key = _timestamp_order_key(str(observation["timestamp"]))
    latest_key = _timestamp_order_key(str(latest[0])) if latest else None
    stale_timestamp = bool(
        incoming_key is not None
        and latest_key is not None
        and incoming_key[0] == latest_key[0]
        and incoming_key[1] < latest_key[1]
    )

    if stale_timestamp:
        return ReplayCheckResult(
            detected=True,
            reason=f"Observation timestamp {observation['timestamp']} predates the latest accepted timestamp {latest[0]}.",
            fingerprint=fingerprint,
            observation_timestamp=str(observation["timestamp"]),
            run_id=observation.get("run_id"),
            session_id=target_session_id,
        )

    return ReplayCheckResult(
        detected=False,
        reason="Observation fingerprint and timestamp are fresh.",
        fingerprint=fingerprint,
        observation_timestamp=str(observation["timestamp"]),
        run_id=observation.get("run_id"),
        session_id=target_session_id,
    )


def record_observation_with_replay_check(
    observation: ObservationRow,
    execution_timestamp: str | None = None,
    session_id: str | None = None,
    db_path: str = cfg.SQLITE_PATH,
) -> ReplayCheckResult:
    """Atomically classify and audit an observation to prevent concurrent reacceptance."""
    target_session_id = (
        session_id
        or observation.session_id
        or get_active_session_id()
    )
    exec_ts = (
        execution_timestamp
        or observation.execution_timestamp
        or datetime.now().isoformat()
    )
    observation_data = observation.model_dump()
    fingerprint = observation.fingerprint or observation_fingerprint(observation_data)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        replay_result = _check_observation_replay_in_connection(
            conn,
            observation_data,
            fingerprint,
            exec_ts,
            target_session_id,
        )
        conn.execute(
            """INSERT INTO observations (
                run_id, session_id, execution_timestamp, fingerprint, replay_detected, replay_reason, timestamp,
                voltage_pu, load_kw, solar_kw, battery_soc_pct,
                battery_temperature_c, transformer_loading_pct
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                observation.run_id,
                target_session_id,
                exec_ts,
                fingerprint,
                int(replay_result.detected),
                replay_result.reason if replay_result.detected else None,
                observation.timestamp,
                observation.voltage_pu,
                observation.load_kw,
                observation.solar_kw,
                observation.battery_soc_pct,
                observation.battery_temperature_c,
                observation.transformer_loading_pct,
            ),
        )
        conn.commit()
        return replay_result
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def insert_observation(obs: ObservationRow, db_path: str = cfg.SQLITE_PATH) -> int:
    conn = sqlite3.connect(db_path)
    try:
        target_session_id = obs.session_id or get_active_session_id()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO observations
            (run_id, session_id, execution_timestamp, fingerprint, replay_detected, replay_reason, timestamp, voltage_pu, load_kw, solar_kw, battery_soc_pct, battery_temperature_c, transformer_loading_pct)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            obs.run_id, target_session_id, obs.execution_timestamp, obs.fingerprint, int(obs.replay_detected), obs.replay_reason,
            obs.timestamp, obs.voltage_pu, obs.load_kw, obs.solar_kw,
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
        cols = {
            row[1]
            for row in cursor.execute("PRAGMA table_info(aegis_decisions)")
        }
        if "session_id" in cols:
            cursor.execute('''
                INSERT INTO aegis_decisions (
                    run_id, session_id, timestamp, action_id, policy_result, provenance_result, behaviour_flag,
                    risk_score, final_decision, reason, human_reviewer, is_injected_attack, attack_type
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                decision.run_id, decision.session_id, decision.timestamp, decision.action_id, decision.policy_result,
                decision.provenance_result, decision.behaviour_flag, decision.risk_score,
                decision.final_decision, decision.reason, decision.human_reviewer,
                decision.is_injected_attack, decision.attack_type
            ))
        else:
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


def consume_report_authorization(
    report_id: str,
    action_id: str,
    session_id: str,
    run_id: str,
    timestamp: str | None = None,
    action_digest: str | None = None,
    db_path: str = cfg.SQLITE_PATH,
) -> bool:
    """
    Atomically attempts to claim and consume an authorization report for an approved action.
    Returns True if consumption succeeded, False if the report was already consumed in this session.
    Raises RuntimeError on unexpected database failures.
    """
    if not report_id or not session_id:
        return False

    conn = sqlite3.connect(db_path, timeout=10.0)
    try:
        conn.execute("BEGIN IMMEDIATE")
        # Ensure table exists even if db was initialized before this feature
        conn.execute("""
            CREATE TABLE IF NOT EXISTS report_consumptions (
                consumption_id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                status TEXT NOT NULL,
                action_digest TEXT
            )
        """)
        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_report_session_consumed 
            ON report_consumptions (report_id, session_id) 
            WHERE status = 'CONSUMED'
        """)
        
        cur = conn.execute(
            """SELECT action_id FROM report_consumptions 
               WHERE report_id = ? AND session_id = ? AND status = 'CONSUMED'""",
            (report_id, session_id),
        )
        existing = cur.fetchone()
        if existing:
            conn.rollback()
            return False

        cols = {row[1] for row in conn.execute("PRAGMA table_info(report_consumptions)")}
        if "action_digest" not in cols:
            conn.execute("ALTER TABLE report_consumptions ADD COLUMN action_digest TEXT")

        ts = timestamp or datetime.now().isoformat()
        conn.execute(
            """INSERT INTO report_consumptions 
               (report_id, action_id, session_id, run_id, timestamp, status, action_digest)
               VALUES (?, ?, ?, ?, ?, 'CONSUMED', ?)""",
            (report_id, action_id, session_id, run_id, ts, action_digest or ""),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        conn.rollback()
        return False
    except Exception as e:
        conn.rollback()
        raise RuntimeError(f"Database error during report consumption: {e}") from e
    finally:
        conn.close()


def persist_decision_and_consume_report(
    decision_row: AEGISDecisionRow,
    report_id: Optional[str] = None,
    action_digest: Optional[str] = None,
    outbox_payload: Optional[dict] = None,
    personnel_evidence: Optional[Any] = None,
    db_path: str = cfg.SQLITE_PATH,
) -> tuple[bool, Optional[int]]:
    """
    Atomically:
    1. If decision_row.final_decision == 'allow' and report_id is provided:
       Claims the authorization report in SQLite within this transaction.
       If already claimed in this session, rolls back and returns (False, None).
    1b. If decision_row.final_decision == 'allow' and personnel_evidence is provided:
       Atomically claims and consumes the personnel credential (nonce) across all sessions.
       If already claimed anywhere, rolls back and returns (False, None).
    2. Persists the decision_row into aegis_decisions.
    3. If outbox_payload is provided, writes to neo4j_outbox table.
    4. Commits all changes in a single BEGIN IMMEDIATE transaction.
    
    If any error occurs during decision persistence, the transaction rolls back completely,
    ensuring a report or credential cannot remain consumed without an auditable explanation.

    Returns:
        (success: bool, decision_id: Optional[int])
        - Returns (False, None) if the report or personnel credential was already claimed.
        - Returns (True, decision_id) on successful atomic commit.
    Raises:
        RuntimeError on unexpected database failures.
    """
    if not decision_row.action_id:
        return False, None

    conn = sqlite3.connect(db_path, timeout=10.0)
    try:
        conn.execute("BEGIN IMMEDIATE")
        
        # 1. Report consumption check/insert if ALLOW
        is_allow = str(decision_row.final_decision).lower() == "allow"
        session_id = decision_row.session_id or DEFAULT_SESSION_ID
        
        if is_allow and report_id:
            # Ensure table & index exist
            conn.execute("""
                CREATE TABLE IF NOT EXISTS report_consumptions (
                    consumption_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    status TEXT NOT NULL,
                    action_digest TEXT
                )
            """)
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_report_session_consumed 
                ON report_consumptions (report_id, session_id) 
                WHERE status = 'CONSUMED'
            """)

            cur = conn.execute(
                """SELECT action_id FROM report_consumptions 
                   WHERE report_id = ? AND session_id = ? AND status = 'CONSUMED'""",
                (report_id, session_id),
            )
            existing = cur.fetchone()
            if existing:
                conn.rollback()
                return False, None

            cols = {row[1] for row in conn.execute("PRAGMA table_info(report_consumptions)")}
            if "action_digest" not in cols:
                conn.execute("ALTER TABLE report_consumptions ADD COLUMN action_digest TEXT")

            ts = decision_row.timestamp or datetime.now().isoformat()
            try:
                conn.execute(
                    """INSERT INTO report_consumptions 
                       (report_id, action_id, session_id, run_id, timestamp, status, action_digest)
                       VALUES (?, ?, ?, ?, ?, 'CONSUMED', ?)""",
                    (report_id, decision_row.action_id, session_id, decision_row.run_id, ts, action_digest or ""),
                )
            except sqlite3.IntegrityError:
                conn.rollback()
                return False, None

        # 1b. Personnel credential consumption check/insert if ALLOW
        if is_allow and personnel_evidence:
            nonce = getattr(personnel_evidence, "nonce", None)
            personnel_id = getattr(personnel_evidence, "personnel_id", None)
            co_signer_id = getattr(personnel_evidence, "co_signer_id", None)

            if nonce and personnel_id:
                # Ensure table & index exist
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS personnel_credential_consumptions (
                        consumption_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        personnel_id TEXT NOT NULL,
                        nonce TEXT NOT NULL,
                        action_id TEXT NOT NULL,
                        session_id TEXT NOT NULL,
                        run_id TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'CONSUMED',
                        action_digest TEXT NOT NULL,
                        co_signer_id TEXT
                    )
                """)
                conn.execute("""
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_personnel_credential_consumed
                    ON personnel_credential_consumptions (personnel_id, nonce)
                    WHERE status = 'CONSUMED'
                """)

                # Check primary personnel nonce consumption
                cur = conn.execute(
                    """SELECT 1 FROM personnel_credential_consumptions 
                       WHERE personnel_id = ? AND nonce = ? AND status = 'CONSUMED' LIMIT 1""",
                    (personnel_id, nonce),
                )
                if cur.fetchone():
                    conn.rollback()
                    return False, None

                # Check co-signer nonce consumption if present
                if co_signer_id:
                    cur = conn.execute(
                        """SELECT 1 FROM personnel_credential_consumptions 
                           WHERE personnel_id = ? AND nonce = ? AND status = 'CONSUMED' LIMIT 1""",
                        (co_signer_id, nonce),
                    )
                    if cur.fetchone():
                        conn.rollback()
                        return False, None

                ts = decision_row.timestamp or datetime.now().isoformat()
                try:
                    conn.execute(
                        """INSERT INTO personnel_credential_consumptions 
                           (personnel_id, nonce, action_id, session_id, run_id, timestamp, status, action_digest, co_signer_id)
                           VALUES (?, ?, ?, ?, ?, ?, 'CONSUMED', ?, ?)""",
                        (personnel_id, nonce, decision_row.action_id, session_id, decision_row.run_id, ts, action_digest or "", co_signer_id),
                    )
                    if co_signer_id and co_signer_id != personnel_id:
                        conn.execute(
                            """INSERT INTO personnel_credential_consumptions 
                               (personnel_id, nonce, action_id, session_id, run_id, timestamp, status, action_digest, co_signer_id)
                               VALUES (?, ?, ?, ?, ?, ?, 'CONSUMED', ?, ?)""",
                            (co_signer_id, nonce, decision_row.action_id, session_id, decision_row.run_id, ts, action_digest or "", personnel_id),
                        )
                except sqlite3.IntegrityError:
                    conn.rollback()
                    return False, None

        # 2. Persist decision row
        cursor = conn.cursor()
        cols = {
            row[1]
            for row in cursor.execute("PRAGMA table_info(aegis_decisions)")
        }
        if "session_id" in cols:
            cursor.execute('''
                INSERT INTO aegis_decisions (
                    run_id, session_id, timestamp, action_id, policy_result,
                    provenance_result, behaviour_flag, risk_score,
                    final_decision, reason, human_reviewer,
                    is_injected_attack, attack_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                decision_row.run_id, session_id, decision_row.timestamp, decision_row.action_id,
                decision_row.policy_result, decision_row.provenance_result, decision_row.behaviour_flag,
                decision_row.risk_score, decision_row.final_decision, decision_row.reason,
                decision_row.human_reviewer, decision_row.is_injected_attack, decision_row.attack_type
            ))
        else:
            cursor.execute('''
                INSERT INTO aegis_decisions (
                    run_id, timestamp, action_id, policy_result,
                    provenance_result, behaviour_flag, risk_score,
                    final_decision, reason, human_reviewer,
                    is_injected_attack, attack_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                decision_row.run_id, decision_row.timestamp, decision_row.action_id,
                decision_row.policy_result, decision_row.provenance_result, decision_row.behaviour_flag,
                decision_row.risk_score, decision_row.final_decision, decision_row.reason,
                decision_row.human_reviewer, decision_row.is_injected_attack, decision_row.attack_type
            ))
        decision_id = cursor.lastrowid

        # 3. Persist outbox event if payload provided
        if outbox_payload is not None:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS neo4j_outbox (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            now_iso = datetime.now().isoformat()
            payload_json = json.dumps(outbox_payload)
            conn.execute(
                """INSERT INTO neo4j_outbox 
                   (event_type, action_id, run_id, session_id, payload, status, retry_count, created_at, updated_at)
                   VALUES ('DECISION_AUDIT', ?, ?, ?, ?, 'PENDING', 0, ?, ?)""",
                (decision_row.action_id, decision_row.run_id, session_id, payload_json, now_iso, now_iso)
            )

        conn.commit()
        return True, decision_id
    except sqlite3.IntegrityError:
        conn.rollback()
        return False, None
    except Exception as e:
        conn.rollback()
        raise RuntimeError(f"Database error during atomic decision persistence: {e}") from e
    finally:
        conn.close()


def sync_neo4j_outbox(
    db_path: str = cfg.SQLITE_PATH,
    neo4j_client=None,
    limit: int = 50,
) -> int:
    """
    Scans neo4j_outbox for PENDING or FAILED events and pushes them to Neo4j.
    Events are processed idempotently.
    Returns the number of events successfully synchronized.
    """
    if neo4j_client is None:
        from provenance.neo4j_client import get_neo4j_client
        neo4j_client = get_neo4j_client()
    if not neo4j_client or not getattr(neo4j_client, "driver", None):
        return 0

    conn = sqlite3.connect(db_path, timeout=10.0)
    synced_count = 0
    try:
        cur = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='neo4j_outbox'")
        if not cur.fetchone():
            return 0

        cur = conn.execute(
            """SELECT event_id, event_type, action_id, run_id, session_id, payload, retry_count
               FROM neo4j_outbox
               WHERE status IN ('PENDING', 'FAILED')
               ORDER BY event_id ASC LIMIT ?""",
            (limit,),
        )
        rows = cur.fetchall()
        for row in rows:
            event_id, event_type, action_id, run_id, session_id, payload_str, retry_count = row
            try:
                payload = json.loads(payload_str)
                aegis_decision = payload.get("aegis_decision", {})
                action_digest = payload.get("action_digest", "")

                success = neo4j_client.log_aegis_decision(
                    action_id=action_id,
                    run_id=run_id,
                    aegis_decision=aegis_decision,
                    session_id=session_id,
                    action_digest=action_digest,
                )
                if success is False:
                    raise RuntimeError(
                        f"Neo4j decision write unverified: Action node not found or decision record not created (action_id={action_id})"
                    )

                now_iso = datetime.now().isoformat()
                conn.execute(
                    """UPDATE neo4j_outbox
                       SET status = 'SENT', updated_at = ?, last_error = NULL
                       WHERE event_id = ?""",
                    (now_iso, event_id),
                )
                conn.commit()
                synced_count += 1
            except Exception as e:
                now_iso = datetime.now().isoformat()
                conn.execute(
                    """UPDATE neo4j_outbox
                       SET status = 'FAILED', retry_count = retry_count + 1, last_error = ?, updated_at = ?
                       WHERE event_id = ?""",
                    (str(e), now_iso, event_id),
                )
                conn.commit()
    finally:
        conn.close()
    return synced_count


def is_report_consumed(
    report_id: str,
    session_id: str,
    db_path: str = cfg.SQLITE_PATH,
) -> bool:
    """Checks whether a report has already been consumed within a session."""
    if not report_id or not session_id:
        return False
    if not os.path.exists(db_path):
        return False
    conn = sqlite3.connect(db_path, timeout=10.0)
    try:
        cur = conn.execute(
            """SELECT 1 FROM sqlite_master WHERE type='table' AND name='report_consumptions'"""
        )
        if not cur.fetchone():
            return False
        cur = conn.execute(
            """SELECT 1 FROM report_consumptions 
               WHERE report_id = ? AND session_id = ? AND status = 'CONSUMED' LIMIT 1""",
            (report_id, session_id),
        )
        return cur.fetchone() is not None
    finally:
        conn.close()


def is_personnel_credential_consumed(
    personnel_id: str,
    nonce: str,
    db_path: str = cfg.SQLITE_PATH,
) -> bool:
    """Checks whether a personnel credential (nonce) has already been consumed globally across all sessions."""
    if not personnel_id or not nonce:
        return False
    if not os.path.exists(db_path):
        return False
    conn = sqlite3.connect(db_path, timeout=10.0)
    try:
        cur = conn.execute(
            """SELECT 1 FROM sqlite_master WHERE type='table' AND name='personnel_credential_consumptions'"""
        )
        if not cur.fetchone():
            return False
        cur = conn.execute(
            """SELECT 1 FROM personnel_credential_consumptions 
               WHERE personnel_id = ? AND nonce = ? AND status = 'CONSUMED' LIMIT 1""",
            (personnel_id, nonce),
        )
        return cur.fetchone() is not None
    finally:
        conn.close()


def consume_personnel_credential(
    personnel_id: str,
    nonce: str,
    action_id: str,
    session_id: str,
    run_id: str,
    timestamp: Optional[str] = None,
    action_digest: Optional[str] = None,
    co_signer_id: Optional[str] = None,
    db_path: str = cfg.SQLITE_PATH,
) -> bool:
    """
    Atomically attempts to consume a personnel credential (nonce) for an approved action.
    Also consumes co-signer credential if co_signer_id is provided.
    Returns True if consumption succeeded, False if already consumed.
    Raises RuntimeError on unexpected database failures.
    """
    if not personnel_id or not nonce:
        return False

    conn = sqlite3.connect(db_path, timeout=10.0)
    try:
        conn.execute("BEGIN IMMEDIATE")
        # Ensure table exists
        conn.execute("""
            CREATE TABLE IF NOT EXISTS personnel_credential_consumptions (
                consumption_id INTEGER PRIMARY KEY AUTOINCREMENT,
                personnel_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                action_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'CONSUMED',
                action_digest TEXT NOT NULL,
                co_signer_id TEXT
            )
        """)
        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_personnel_credential_consumed
            ON personnel_credential_consumptions (personnel_id, nonce)
            WHERE status = 'CONSUMED'
        """)

        # Check primary personnel
        cur = conn.execute(
            """SELECT 1 FROM personnel_credential_consumptions 
               WHERE personnel_id = ? AND nonce = ? AND status = 'CONSUMED' LIMIT 1""",
            (personnel_id, nonce),
        )
        if cur.fetchone():
            conn.rollback()
            return False

        # Check co-signer if present
        if co_signer_id:
            cur = conn.execute(
                """SELECT 1 FROM personnel_credential_consumptions 
                   WHERE personnel_id = ? AND nonce = ? AND status = 'CONSUMED' LIMIT 1""",
                (co_signer_id, nonce),
            )
            if cur.fetchone():
                conn.rollback()
                return False

        ts = timestamp or datetime.now().isoformat()
        try:
            conn.execute(
                """INSERT INTO personnel_credential_consumptions 
                   (personnel_id, nonce, action_id, session_id, run_id, timestamp, status, action_digest, co_signer_id)
                   VALUES (?, ?, ?, ?, ?, ?, 'CONSUMED', ?, ?)""",
                (personnel_id, nonce, action_id, session_id, run_id, ts, action_digest or "", co_signer_id),
            )
            if co_signer_id and co_signer_id != personnel_id:
                conn.execute(
                    """INSERT INTO personnel_credential_consumptions 
                       (personnel_id, nonce, action_id, session_id, run_id, timestamp, status, action_digest, co_signer_id)
                       VALUES (?, ?, ?, ?, ?, ?, 'CONSUMED', ?, ?)""",
                    (co_signer_id, nonce, action_id, session_id, run_id, ts, action_digest or "", personnel_id),
                )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            conn.rollback()
            return False
    except Exception as e:
        conn.rollback()
        raise RuntimeError(f"Database error during personnel credential consumption: {e}") from e
    finally:
        conn.close()

def query_recent_observations(
    n: int,
    db_path: str = cfg.SQLITE_PATH,
    session_id: str | None = None,
) -> List[Dict[str, Any]]:
    """Returns the `n` most recent observations in chronological order, optionally scoped to a session."""
    conn = sqlite3.connect(db_path)
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if session_id is not None:
            cursor.execute('''
                SELECT * FROM observations
                WHERE COALESCE(replay_detected, 0) = 0
                  AND COALESCE(session_id, 'default_session') = ?
                ORDER BY obs_id DESC LIMIT ?
            ''', (session_id, n))
        else:
            cursor.execute('''
                SELECT * FROM observations
                WHERE COALESCE(replay_detected, 0) = 0
                ORDER BY obs_id DESC LIMIT ?
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
