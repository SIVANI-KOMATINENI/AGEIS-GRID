"""
config.py — Central configuration for AEGIS Grid.
All values are read from .env (or environment variables).
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the project root (this file's directory)
_env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=_env_path)

# ── Ollama ────────────────────────────────────────────────────────────────────
OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")

# ── Neo4j ─────────────────────────────────────────────────────────────────────
NEO4J_URI: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "password")
NEO4J_DATABASE: str = os.getenv("NEO4J_DATABASE", "neo4j")

# ── SQLite ────────────────────────────────────────────────────────────────────
_sqlite_rel = os.getenv("SQLITE_PATH", "data/logs/aegis_audit.db")
SQLITE_PATH: str = str(Path(__file__).parent / _sqlite_rel)

# ── Simulation ────────────────────────────────────────────────────────────────
SIM_TIMESTEP_MINUTES: int = int(os.getenv("SIM_TIMESTEP_MINUTES", "1"))
SIM_DURATION_HOURS: int = int(os.getenv("SIM_DURATION_HOURS", "24"))

# ── Data paths ────────────────────────────────────────────────────────────────
DATA_DIR: Path = Path(__file__).parent / "data"
MICROGRID_CSV: str = str(DATA_DIR / "microgrid" / "microgrid_observations.csv")
ATTACK_LOG: str = str(DATA_DIR / "attacks" / "attack_events.csv")
LOG_DIR: str = str(DATA_DIR / "logs")

# ── AEGIS Risk weights ────────────────────────────────────────────────────────
RISK_WEIGHT_POLICY: float = 0.40
RISK_WEIGHT_PROVENANCE: float = 0.40
RISK_WEIGHT_BEHAVIOUR: float = 0.20

# Low/Medium/High risk thresholds
RISK_BAND_MEDIUM: float = 0.40   # >= this → MEDIUM
RISK_BAND_HIGH: float = 0.70     # >= this → HIGH

# ── Behaviour Analysis ────────────────────────────────────────────────────────
BEHAVIOUR_HISTORY_SIZE: int = 20   # number of recent actions to track per agent
