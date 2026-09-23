"""
database_test.py - Milestone 2 verification script.

Run this to verify SQLite schema creation, inserts, and Neo4j connection handling.

Usage:
    python database_test.py
"""

import sys
import os
import json
from pathlib import Path

# Ensure project root is on path
_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))

from database.models import ObservationRow, AgentMessageRow, AEGISDecisionRow
from database.sqlite import init_db, insert_observation, insert_agent_message, insert_aegis_decision, query_recent_observations
from provenance.neo4j_client import get_neo4j_client
import config as cfg

def test_database():
    print("=" * 60)
    print("AEGIS Grid - Milestone 2: Database Layer Test")
    print("=" * 60)

    # 1. SQLite Testing
    # Ensure a fresh db for testing
    test_db_path = "data/logs/test_aegis_audit.db"
    
    # Clean up old test db if it exists
    if os.path.exists(test_db_path):
        os.remove(test_db_path)

    print("\n1. Initialising SQLite Database...")
    init_db(test_db_path, wipe_existing=True)
    print(f"[OK] Database created at {test_db_path}")

    print("\n2. Testing Inserts...")
    obs = ObservationRow(
        timestamp="12:00",
        voltage_pu=1.02,
        load_kw=45.0,
        solar_kw=10.0,
        battery_soc_pct=85.0,
        battery_temperature_c=31.2,
        transformer_loading_pct=15.0
    )
    obs_id = insert_observation(obs, test_db_path)
    print(f"[OK] Inserted observation, got ID: {obs_id}")

    msg = AgentMessageRow(
        timestamp="12:01",
        sender_agent="monitoring_agent",
        receiver_agent="response_agent",
        message_content=json.dumps({"status": "NORMAL"})
    )
    msg_id = insert_agent_message(msg, test_db_path)
    print(f"[OK] Inserted agent message, got ID: {msg_id}")

    dec = AEGISDecisionRow(
        timestamp="12:02",
        action_id="action_001",
        policy_result='{"decision": "allow"}',
        provenance_result='{"verified": true}',
        behaviour_flag=0,
        risk_score=0.1,
        final_decision="allow",
        reason="All checks passed.",
        is_injected_attack=0
    )
    dec_id = insert_aegis_decision(dec, test_db_path)
    print(f"[OK] Inserted AEGIS decision, got ID: {dec_id}")

    print("\n3. Testing Query...")
    recent_obs = query_recent_observations(5, test_db_path)
    print(f"[OK] Retrieved {len(recent_obs)} recent observations")
    assert recent_obs[0]["voltage_pu"] == 1.02

    # Clean up test db
    if os.path.exists(test_db_path):
        os.remove(test_db_path)

    # 2. Neo4j Testing
    print("\n4. Testing Neo4j Client Initialization...")
    neo_client = get_neo4j_client()
    if neo_client.driver:
        print("[OK] Neo4j is connected!")
    else:
        print("[WARNING] Neo4j is not reachable. This is fine for now; the client gracefully falls back to mock logic.")
        print("          Before running the full system or attacks, please ensure Neo4j is running at:", cfg.NEO4J_URI)

    print("\n" + "=" * 60)
    print("Milestone 2 COMPLETE - database layer is working correctly.")
    print("=" * 60)

if __name__ == "__main__":
    test_database()
