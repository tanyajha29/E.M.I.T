from app.db.repositories.case_repository import CaseRepository
from app.schemas.case import Case, CaseCreate, CaseUpdate
from datetime import datetime

class CaseService:
    def __init__(self):
        self.repository = CaseRepository()

    def create_case(self, case_in: CaseCreate) -> Case:
        case_data = Case(
            name=case_in.name,
            description=case_in.description
        )
        inserted = self.repository.insert_one(case_data.model_dump())
        return Case(**inserted)

    def get_case(self, case_id: str) -> Case | None:
        case_dict = self.repository.find_one({"case_id": case_id})
        return Case(**case_dict) if case_dict else None

    def get_all_cases(self) -> list[Case]:
        cases_list = self.repository.find_all({})
        return [Case(**c) for c in cases_list]

    def update_case(self, case_id: str, case_in: CaseUpdate) -> Case | None:
        case_dict = self.repository.find_one({"case_id": case_id})
        if not case_dict:
            return None
        
        update_data = case_in.model_dump(exclude_unset=True)
        update_data["updated_at"] = datetime.utcnow()
        
        self.repository.update_one({"case_id": case_id}, update_data)
        updated_dict = self.repository.find_one({"case_id": case_id})
        return Case(**updated_dict) if updated_dict else None

    def delete_case(self, case_id: str) -> bool:
        return self.repository.delete_one({"case_id": case_id})
