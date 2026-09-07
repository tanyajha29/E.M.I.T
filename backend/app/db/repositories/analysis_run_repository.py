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

    def update_stage(self, analysis_id: str, stage: str, status: str, progress_percent: int = None, errors: list = None, warnings: list = None) -> bool:
        update_data = {
            "current_stage": stage,
            "status": status,
            "updated_at": datetime.utcnow()
        }
        if progress_percent is not None:
            update_data["progress_percent"] = max(0, min(100, int(progress_percent)))
        if errors is not None:
            update_data["errors"] = errors
        if warnings is not None:
            update_data["warnings"] = warnings
        return self.update_one({"analysis_id": analysis_id}, update_data)

    def update_provider_result(self, analysis_id: str, provider_name: str, provider_record: dict, progress_percent: int = None) -> bool:
        query = {"analysis_id": analysis_id}
        # Safely updates both provider_results and providers dictionary keys
        update_data = {
            f"provider_results.{provider_name}": provider_record,
            f"providers.{provider_name}": provider_record,
            "updated_at": datetime.utcnow()
        }
        if progress_percent is not None:
            update_data["progress_percent"] = max(0, min(100, int(progress_percent)))
        result = self.collection.update_one(query, {"$set": update_data})
        return result.modified_count > 0

    def update_provider_status(self, analysis_id: str, provider_name: str, status: str, message: str = None, started_at: datetime = None, progress_percent: int = None) -> bool:
        query = {"analysis_id": analysis_id}
        update_data = {
            f"provider_results.{provider_name}.status": status,
            f"providers.{provider_name}.status": status,
            "updated_at": datetime.utcnow()
        }
        if message is not None:
            update_data[f"provider_results.{provider_name}.message"] = message
            update_data[f"providers.{provider_name}.message"] = message
        if started_at is not None:
            update_data[f"provider_results.{provider_name}.started_at"] = started_at
            update_data[f"providers.{provider_name}.started_at"] = started_at
        if progress_percent is not None:
            update_data["progress_percent"] = max(0, min(100, int(progress_percent)))
        result = self.collection.update_one(query, {"$set": update_data})
        return result.modified_count > 0

    def complete(self, analysis_id: str, status: str, completed_at: datetime, errors: list, warnings: list, progress_percent: int = 100) -> bool:
        update_data = {
            "status": status,
            "current_stage": "COMPLETED" if status in ["COMPLETED", "PARTIAL"] else "FAILED",
            "progress_percent": progress_percent,
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
            "progress_percent": 100,
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
