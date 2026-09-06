import os
import sys
from datetime import datetime
from uuid import uuid4
from pymongo import MongoClient

# Add the backend root directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.config import settings
from app.core.security import hash_password

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
        "users",
        "sessions",
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
        # users index definitions
        db.users.create_index("user_id", unique=True)
        db.users.create_index("email", unique=True)
        db.users.create_index("role")

        # sessions index definitions
        db.sessions.create_index("session_id", unique=True)
        db.sessions.create_index("user_id")
        db.sessions.create_index("expires_at", expireAfterSeconds=0)

        # cases index definitions
        db.cases.create_index("case_id", unique=True)
        db.cases.create_index("owner_id")
        db.cases.create_index("assigned_user_ids")
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

    # Idempotent Admin Bootstrap
    bootstrap_admin_id = None
    if settings.INITIAL_ADMIN_EMAIL and settings.INITIAL_ADMIN_PASSWORD:
        admin_email = settings.INITIAL_ADMIN_EMAIL.strip().lower()
        existing_admin = db.users.find_one({"email": admin_email})
        if not existing_admin:
            bootstrap_admin_id = str(uuid4())
            admin_user = {
                "user_id": bootstrap_admin_id,
                "email": admin_email,
                "password_hash": hash_password(settings.INITIAL_ADMIN_PASSWORD),
                "full_name": "System Administrator",
                "role": "ADMIN",
                "badge_id": "EMIT-ADMIN-0001",
                "is_active": True,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            }
            db.users.insert_one(admin_user)
            print(f"Bootstrap ADMIN created: {admin_email} (ID: {bootstrap_admin_id})")
        else:
            bootstrap_admin_id = existing_admin.get("user_id")
            print(f"Bootstrap ADMIN already exists: {admin_email}")
    else:
        # Check if an existing admin exists
        first_admin = db.users.find_one({"role": "ADMIN"})
        if first_admin:
            bootstrap_admin_id = first_admin.get("user_id")

    # Idempotent Legacy Cases Migration:
    # Any cases without owner_id should be safely assigned to the system administrator or default owner
    target_owner_id = bootstrap_admin_id or "system_admin_legacy"
    target_owner_name = "System Administrator" if bootstrap_admin_id else "Legacy System"
    legacy_query = {
        "$or": [
            {"owner_id": {"$exists": False}},
            {"owner_id": None},
            {"owner_id": ""}
        ]
    }
    legacy_count = db.cases.count_documents(legacy_query)
    if legacy_count > 0:
        print(f"Migrating {legacy_count} legacy case(s) without owner_id...")
        result = db.cases.update_many(
            legacy_query,
            {
                "$set": {
                    "owner_id": target_owner_id,
                    "owner_name": target_owner_name,
                    "assigned_user_ids": []
                }
            }
        )
        print(f"Legacy cases migration complete: {result.modified_count} updated.")
    else:
        print("No legacy unowned cases found.")

    print("\nDatabase initialization complete.")

if __name__ == "__main__":
    init_db()
