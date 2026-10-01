"""
provenance/neo4j_client.py
Functions to log and trace authority chains via Neo4j graph database.

Nodes: Sensor, Telemetry, MonitoringAgent, Report, ResponseAgent, Action, Evidence, Attacker
Relationships: GENERATED, RECEIVED_BY, PROPOSED, VERIFIED_BY, DERIVED_FROM, INJECTED
"""

import logging
from neo4j import GraphDatabase, exceptions

import config as cfg

logger = logging.getLogger(__name__)

class Neo4jClient:
    def __init__(self, uri=cfg.NEO4J_URI, user=cfg.NEO4J_USER, password=cfg.NEO4J_PASSWORD):
        self.uri = uri
        self.user = user
        self.password = password
        self.driver = None
        self._connect()

    def _connect(self):
        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            self.driver.verify_connectivity()
            logger.info("Successfully connected to Neo4j.")
        except Exception as e:
            logger.warning(f"Failed to connect to Neo4j at {self.uri}: {e}. Provenance features will be disabled/mocked.")
            self.driver = None

    def close(self):
        if self.driver:
            self.driver.close()

    def wipe_graph(self):
        """Wipes the entire graph (use for fresh eval runs)."""
        if not self.driver:
            return
        query = "MATCH (n) DETACH DELETE n"
        with self.driver.session(database=cfg.NEO4J_DATABASE) as session:
            session.run(query)

    def log_action_provenance(self, observation, report, proposed_action):
        """Persists the observation, report, and proposed action before verification."""
        if not self.driver:
            return
            
        timestamp = observation["timestamp"]
        run_id = observation["run_id"]
        action_id = proposed_action["action_id"]
        obs_id = f"obs_{timestamp}"
        report_id = report["report_id"]

        if report.get("run_id") != run_id or proposed_action.get("run_id") != run_id:
            raise ValueError("Observation, report, and action run_id values must match")

        # Using a unified Cypher statement to MERGE all relevant entities and CREATE relationships.
        # MERGE creates the node only if it doesn't already exist.
        query = """
        // 1. Telemetry layer
        MERGE (s:Sensor {name: 'microgrid_sim', run_id: $run_id})
        MERGE (t:Telemetry {id: $obs_id, run_id: $run_id})
          ON CREATE SET t.timestamp = $timestamp, t.data = $observation_json
        MERGE (s)-[:GENERATED]->(t)
        
        // 2. Monitoring Agent layer
        MERGE (mon:MonitoringAgent {name: 'monitoring_agent', run_id: $run_id})
        MERGE (t)-[:RECEIVED_BY]->(mon)
        
        MERGE (r:Report {id: $report_id, run_id: $run_id})
          ON CREATE SET r.status = $status, r.severity = $severity
        MERGE (mon)-[:GENERATED]->(r)
        
        // 3. Response Agent layer
        MERGE (res:ResponseAgent {name: 'response_agent', run_id: $run_id})
        MERGE (r)-[:RECEIVED_BY]->(res)
        
        MERGE (a:Action {id: $action_id, run_id: $run_id})
          ON CREATE SET a.action_type = $action_type, 
                        a.target = $target, 
                        a.claimed_authorization = $auth
        MERGE (res)-[:PROPOSED]->(a)
        
        """
        
        import json
        parameters = {
            "obs_id": obs_id,
            "run_id": run_id,
            "timestamp": timestamp,
            "observation_json": json.dumps(observation),
            "report_id": report_id,
            "status": report.get("status", "UNKNOWN"),
            "severity": report.get("severity", "UNKNOWN"),
            "action_id": action_id,
            "action_type": proposed_action.get("action_type", "UNKNOWN"),
            "target": proposed_action.get("target", "UNKNOWN"),
            "auth": proposed_action.get("claimed_authorization", ""),
        }

        try:
            with self.driver.session(database=cfg.NEO4J_DATABASE) as session:
                session.run(query, parameters)
        except Exception as e:
            logger.error(f"Failed to log action provenance in Neo4j: {e}")

    def log_aegis_decision(self, action_id: str, run_id: str, aegis_decision):
        """Appends the controller's decision to an already persisted action."""
        if not self.driver:
            return
        if aegis_decision.get("run_id") != run_id:
            raise ValueError("AEGIS decision run_id does not match workflow run_id")

        query = """
        MATCH (a:Action {id: $action_id, run_id: $run_id})
        MERGE (d:AEGISDecision {action_id: $action_id, run_id: $run_id})
          ON CREATE SET d.final_decision = $final_decision
        MERGE (a)-[:VERIFIED_BY]->(d)
        """

        try:
            with self.driver.session(database=cfg.NEO4J_DATABASE) as session:
                session.run(
                    query,
                    action_id=action_id,
                    run_id=run_id,
                    final_decision=aegis_decision.get("final_decision", "UNKNOWN"),
                )
        except Exception as e:
            logger.error(f"Failed to log AEGIS decision in Neo4j: {e}")

    def log_full_action_chain(self, observation, report, proposed_action, aegis_decision):
        """Compatibility wrapper for writing a completed action chain."""
        self.log_action_provenance(observation, report, proposed_action)
        self.log_aegis_decision(
            proposed_action["action_id"],
            proposed_action["run_id"],
            aegis_decision,
        )

    def trace_provenance(self, action_id: str) -> list:
        """
        Returns the chain of entities leading to a specific action_id.
        """
        if not self.driver:
            # Stand-in default when Neo4j is unavailable
            return [{"node": "Database Unreachable", "type": "Error"}]
            
        # Match from Action back through PROPOSED, RECEIVED_BY, GENERATED relationships
        query = """
        MATCH path = (node)-[*]->(a:Action {id: $action_id})
        RETURN [x in nodes(path) | {labels: labels(x), attrs: properties(x)}] as trace
        LIMIT 1
        """
        
        try:
            with self.driver.session(database=cfg.NEO4J_DATABASE) as session:
                result = session.run(query, action_id=action_id)
                record = result.single()
                if record:
                    return record["trace"]
        except Exception as e:
            logger.error(f"Failed to trace provenance in Neo4j: {e}")
            
        return []

    def authorization_status(self, claimed_auth: str, action_id: str, run_id: str) -> str:
        """Check that the claimed Report is connected to the exact proposed Action."""
        if not self.driver:
            return "unavailable"
        if not claimed_auth or not action_id or not run_id:
            return "invalid_claim"

        query = """
        OPTIONAL MATCH (r:Report {id: $claimed_authorization, run_id: $run_id})
        WITH r
        OPTIONAL MATCH (m:MonitoringAgent {run_id: $run_id})-[:GENERATED]->(r)
        WITH r, m
        OPTIONAL MATCH (r)-[:RECEIVED_BY]->(res:ResponseAgent {run_id: $run_id})
                  -[:PROPOSED]->(a:Action {id: $action_id, run_id: $run_id})
        RETURN r IS NOT NULL AS report_exists,
               m IS NOT NULL AS monitoring_link_exists,
               res IS NOT NULL AS response_link_exists,
               a IS NOT NULL AS action_exists,
               a.claimed_authorization = $claimed_authorization AS claim_matches
        """

        try:
            with self.driver.session(database=cfg.NEO4J_DATABASE) as session:
                record = session.run(
                    query,
                    claimed_authorization=claimed_auth,
                    action_id=action_id,
                    run_id=run_id,
                ).single()
                if not record:
                    return "unavailable"
                if not record["report_exists"]:
                    return "report_missing"
                if all(
                    record[key]
                    for key in (
                        "monitoring_link_exists",
                        "response_link_exists",
                        "action_exists",
                        "claim_matches",
                    )
                ):
                    return "verified"
                return "unlinked"
        except Exception as e:
            logger.error(f"Failed to verify action provenance in Neo4j: {e}")
            return "unavailable"

    def verify_authorization(
        self,
        claimed_auth: str,
        action_id: str = "",
        run_id: str = "",
    ) -> bool:
        """Compatibility wrapper; authorization requires a complete action chain."""
        return self.authorization_status(claimed_auth, action_id, run_id) == "verified"

# Global singleton client instance
_client = None

def get_neo4j_client() -> Neo4jClient:
    global _client
    if _client is None:
        _client = Neo4jClient()
    return _client
