import os
import sys
from pymongo import MongoClient

# Add the backend root directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.config import settings

def init_db():
    print(f"Connecting to MongoDB at: {settings.MONGODB_URI}...")
    try:
        client = MongoClient(settings.MONGODB_URI, serverSelectionTimeoutMS=5000)
        # Verify connection immediately using ping command
        client.admin.command("ping")
        print("MongoDB connection verified successfully.")
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}", file=sys.stderr)
        sys.exit(1)

    db = client[settings.MONGODB_DATABASE]
    print(f"Using database: {settings.MONGODB_DATABASE}")

    collections = [
        "cases",
        "evidence_files",
        "apk_analyses",
        "network_analyses",
        "indicators",
        "observations",
        "correlations",
        "attack_nodes",
        "attack_edges",
        "threat_intelligence",
        "risk_assessments",
        "reports",
        "analysis_runs"
    ]

    # Create collections if they do not exist
    existing_collections = db.list_collection_names()
    for col in collections:
        if col not in existing_collections:
            db.create_collection(col)
            print(f"Created collection: {col}")
        else:
            print(f"Collection already exists: {col}")

    # Set up indexes (idempotent, existing index definitions are skipped or overwritten safely)
    print("Initializing indexes...")
    try:
        # cases index definitions
        db.cases.create_index("case_id", unique=True)
        db.cases.create_index("status")
        db.cases.create_index("created_at")

        # evidence_files index definitions
        db.evidence_files.create_index("evidence_id", unique=True)
        db.evidence_files.create_index("case_id")
        db.evidence_files.create_index("sha256")
        db.evidence_files.create_index([("case_id", 1), ("sha256", 1)], unique=True)

        # apk_analyses index definitions
        db.apk_analyses.create_index("analysis_id", unique=True)
        db.apk_analyses.create_index("case_id")
        db.apk_analyses.create_index("evidence_id")
        db.apk_analyses.create_index("status")

        # network_analyses index definitions
        db.network_analyses.create_index("analysis_id", unique=True)
        db.network_analyses.create_index("case_id")
        db.network_analyses.create_index("evidence_id")
        db.network_analyses.create_index("status")

        # indicators index definitions
        db.indicators.create_index("indicator_id", unique=True)
        db.indicators.create_index("case_id")
        db.indicators.create_index("type")
        db.indicators.create_index("normalized_value")
        db.indicators.create_index([("case_id", 1), ("type", 1), ("normalized_value", 1)], unique=True)

        # observations index definitions
        db.observations.create_index("observation_id", unique=True)
        db.observations.create_index("case_id")
        db.observations.create_index("evidence_id")
        db.observations.create_index("indicator_id")
        db.observations.create_index("observed_at")

        # correlations index definitions
        db.correlations.create_index("correlation_id", unique=True)
        db.correlations.create_index("case_id")
        db.correlations.create_index("relationship_type")

        # attack_nodes index definitions
        db.attack_nodes.create_index("node_id", unique=True)
        db.attack_nodes.create_index("case_id")
        db.attack_nodes.create_index("node_type")

        # attack_edges index definitions
        db.attack_edges.create_index("edge_id", unique=True)
        db.attack_edges.create_index("case_id")
        db.attack_edges.create_index("source_node_id")
        db.attack_edges.create_index("target_node_id")

        # threat_intelligence index definitions
        db.threat_intelligence.create_index("threat_intel_id", unique=True)
        db.threat_intelligence.create_index("case_id")
        db.threat_intelligence.create_index("indicator_id")

        # risk_assessments index definitions
        db.risk_assessments.create_index("risk_assessment_id", unique=True)
        db.risk_assessments.create_index("case_id")
        db.risk_assessments.create_index("created_at")

        # reports index definitions
        db.reports.create_index("report_id", unique=True)
        db.reports.create_index("case_id")
        db.reports.create_index("status")
        db.reports.create_index("created_at")

        # analysis_runs index definitions
        db.analysis_runs.create_index("analysis_id", unique=True)
        db.analysis_runs.create_index("case_id")
        db.analysis_runs.create_index("evidence_id")
        db.analysis_runs.create_index("created_at")
        db.analysis_runs.create_index("status")

        print("Indexes created successfully.")
    except Exception as e:
        print(f"Error creating indexes: {e}", file=sys.stderr)
        sys.exit(1)

    # Report existing indexes for debugging verification
    print("\nExisting indexes:")
    for col in collections:
        index_info = db[col].index_information()
        print(f" - Collection {col}: {list(index_info.keys())}")

    print("\nDatabase initialization complete.")

if __name__ == "__main__":
    init_db()
