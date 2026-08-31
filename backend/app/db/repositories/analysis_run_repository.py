from app.db.repositories.base import BaseRepository
from datetime import datetime

class AnalysisRunRepository(BaseRepository):
    def __init__(self):
        super().__init__("analysis_runs")

    def create(self, run: dict) -> dict:
        return self.insert_one(run)

    def get_by_id(self, analysis_id: str) -> dict | None:
        return self.find_one({"analysis_id": analysis_id})

    def list_by_case(self, case_id: str) -> list[dict]:
        return self.find_all({"case_id": case_id})

    def update_stage(self, analysis_id: str, stage: str, status: str, errors: list = None, warnings: list = None) -> bool:
        update_data = {
            "current_stage": stage,
            "status": status,
            "updated_at": datetime.utcnow()
        }
        if errors is not None:
            update_data["errors"] = errors
        if warnings is not None:
            update_data["warnings"] = warnings
        return self.update_one({"analysis_id": analysis_id}, update_data)

    def update_provider_result(self, analysis_id: str, provider_name: str, provider_record: dict) -> bool:
        query = {"analysis_id": analysis_id}
        # Safely updates nested provider execution metrics dictionary keys
        update_data = {
            f"provider_results.{provider_name}": provider_record,
            "updated_at": datetime.utcnow()
        }
        result = self.collection.update_one(query, {"$set": update_data})
        return result.modified_count > 0

    def complete(self, analysis_id: str, status: str, completed_at: datetime, errors: list, warnings: list) -> bool:
        update_data = {
            "status": status,
            "current_stage": "COMPLETED" if status in ["COMPLETED", "PARTIAL"] else "FAILED",
            "completed_at": completed_at,
            "errors": errors,
            "warnings": warnings,
            "updated_at": datetime.utcnow()
        }
        return self.update_one({"analysis_id": analysis_id}, update_data)

    def fail(self, analysis_id: str, error_message: str, completed_at: datetime) -> bool:
        query = {"analysis_id": analysis_id}
        update_data = {
            "status": "FAILED",
            "current_stage": "FAILED",
            "completed_at": completed_at,
            "updated_at": datetime.utcnow()
        }
        result = self.collection.update_one(
            query,
            {
                "$set": update_data,
                "$push": {"errors": error_message}
            }
        )
        return result.modified_count > 0
