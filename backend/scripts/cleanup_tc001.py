import sys
import os
sys.path.insert(0, os.path.abspath('.'))

from app.db.repositories.analysis_run_repository import AnalysisRunRepository

def cleanup_failed_analyses():
    case_id = "27523a5d-b123-4f37-a037-9d7f1175a936"
    ar = AnalysisRunRepository()
    runs = ar.find_all({"case_id": case_id})
    print(f"Total runs found for case {case_id}: {len(runs)}")
    for r in runs:
        analysis_id = r.get("analysis_id")
        status = r.get("status")
        provider_results = r.get("provider_results", {})
        has_failed_provider = any(rec.get("status") == "FAILED" or rec.get("status") == "UNAVAILABLE" for rec in provider_results.values() if isinstance(rec, dict))
        
        # If the run was not 100% successful or marked PARTIAL/FAILED
        if status in ["PARTIAL", "FAILED", "PENDING"] or has_failed_provider:
            print(f"Deleting failed/partial run: {analysis_id} (Status: {status})")
            ar.delete_one({"analysis_id": analysis_id})
        else:
            print(f"Keeping completed run: {analysis_id}")

    remaining = ar.find_all({"case_id": case_id})
    print(f"Remaining runs for case {case_id}: {len(remaining)}")

if __name__ == '__main__':
    cleanup_failed_analyses()
