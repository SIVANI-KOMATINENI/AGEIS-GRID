from dotenv import load_dotenv
from neo4j import GraphDatabase
import os

load_dotenv()

URI = os.getenv("NEO4J_URI")
USER = os.getenv("NEO4J_USER")
PASSWORD = os.getenv("NEO4J_PASSWORD")

if __name__ == "__main__":
    print("URI:", URI)
    print("User:", USER)

    try:
        with GraphDatabase.driver(
            URI,
            auth=(USER, PASSWORD)
        ) as driver:

            driver.verify_connectivity()

            print("[OK] AuraDB connection successful!")

    except Exception as e:
        print("[FAIL] Connection failed:")
        print(e)