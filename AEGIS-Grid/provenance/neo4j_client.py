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
        with self.driver.session() as session:
            session.run(query)

    def log_full_action_chain(self, observation, report, proposed_action, aegis_decision):
        """
        Logs a full sequence of events from sensor to AEGIS decision.
        This writes nodes and relationships representing the causality chain.
        """
        if not self.driver:
            return
            
        timestamp = proposed_action.get("timestamp", "unknown")
        action_id = proposed_action["action_id"]
        obs_id = f"obs_{timestamp}"
        report_id = f"rep_{timestamp}"

        # Using a unified Cypher statement to MERGE all relevant entities and CREATE relationships.
        # MERGE creates the node only if it doesn't already exist.
        query = """
        // 1. Telemetry layer
        MERGE (s:Sensor {name: 'microgrid_sim'})
        MERGE (t:Telemetry {id: $obs_id})
          ON CREATE SET t.timestamp = $timestamp, t.data = $observation_json
        MERGE (s)-[:GENERATED]->(t)
        
        // 2. Monitoring Agent layer
        MERGE (mon:MonitoringAgent {name: 'monitoring_agent'})
        MERGE (t)-[:RECEIVED_BY]->(mon)
        
        MERGE (r:Report {id: $report_id})
          ON CREATE SET r.status = $status, r.severity = $severity
        MERGE (mon)-[:GENERATED]->(r)
        
        // 3. Response Agent layer
        MERGE (res:ResponseAgent {name: 'response_agent'})
        MERGE (r)-[:RECEIVED_BY]->(res)
        
        MERGE (a:Action {id: $action_id})
          ON CREATE SET a.action_type = $action_type, 
                        a.target = $target, 
                        a.claimed_authorization = $auth
        MERGE (res)-[:PROPOSED]->(a)
        
        // 4. AEGIS Decision layer
        MERGE (d:AEGISDecision {action_id: $action_id})
          ON CREATE SET d.final_decision = $final_decision
        MERGE (a)-[:VERIFIED_BY]->(d)
        """
        
        import json
        parameters = {
            "obs_id": obs_id,
            "timestamp": timestamp,
            "observation_json": json.dumps(observation),
            "report_id": report_id,
            "status": report.get("status", "UNKNOWN"),
            "severity": report.get("severity", "UNKNOWN"),
            "action_id": action_id,
            "action_type": proposed_action.get("action_type", "UNKNOWN"),
            "target": proposed_action.get("target", "UNKNOWN"),
            "auth": proposed_action.get("claimed_authorization", ""),
            "final_decision": aegis_decision.get("final_decision", "UNKNOWN")
        }

        try:
            with self.driver.session() as session:
                session.run(query, parameters)
        except Exception as e:
            logger.error(f"Failed to log provenance trace in Neo4j: {e}")

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
            with self.driver.session() as session:
                result = session.run(query, action_id=action_id)
                record = result.single()
                if record:
                    return record["trace"]
        except Exception as e:
            logger.error(f"Failed to trace provenance in Neo4j: {e}")
            
        return []

    def verify_authorization(self, claimed_auth: str) -> bool:
        """
        Check if a given authorization token actually exists in the graph.
        (e.g., verifying it was genuinely issued by a prior Report or Evidence node)
        """
        if not self.driver or not claimed_auth:
            # If no graph, or no auth claimed, pass. (Fake auth relies on the claim failing.)
            return True
            
        query = """
        MATCH (n) 
        WHERE n.id = $auth 
           OR n.authorization_token = $auth
           OR n.report_id = $auth
        RETURN count(n) > 0 as verified
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query, auth=claimed_auth)
                return result.single()["verified"]
        except Exception as e:
            logger.error(f"Failed to verify authorization in Neo4j: {e}")
            return False

# Global singleton client instance
_client = None

def get_neo4j_client() -> Neo4jClient:
    global _client
    if _client is None:
        _client = Neo4jClient()
    return _client
