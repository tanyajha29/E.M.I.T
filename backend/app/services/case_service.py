from datetime import datetime
from typing import Optional, List
from fastapi import HTTPException, status

from app.db.repositories.case_repository import CaseRepository
from app.schemas.case import Case, CaseCreate, CaseUpdate
from app.schemas.user import UserOut, UserRole

class CaseService:
    def __init__(self):
        self.repository = CaseRepository()

    def is_case_authorized(self, case_dict: dict, current_user: Optional[UserOut], allow_viewer: bool = True) -> bool:
        if not current_user:
            return True
        if current_user.role == UserRole.ADMIN:
            return True
        owner_id = case_dict.get("owner_id")
        if current_user.role == UserRole.INVESTIGATOR:
            is_owner = bool(owner_id and owner_id == current_user.user_id)
            is_assigned = current_user.user_id in case_dict.get("assigned_user_ids", [])
            return is_owner or is_assigned
        if current_user.role == UserRole.VIEWER:
            if not allow_viewer:
                return False
            return current_user.user_id in case_dict.get("assigned_user_ids", [])
        return False

    def verify_case_access(self, case_id: str, current_user: Optional[UserOut], allow_viewer: bool = True) -> Case:
        case_dict = self.repository.find_one({"case_id": case_id})
        if not case_dict:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
        if not self.is_case_authorized(case_dict, current_user, allow_viewer=allow_viewer):
            # Return 404 to avoid leaking existence of another user's case
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
        return Case(**case_dict)

    def create_case(self, case_in: CaseCreate, current_user: Optional[UserOut] = None) -> Case:
        owner_id = current_user.user_id if current_user else "system"
        owner_name = current_user.full_name if current_user else "System Investigator"
        
        case_data = Case(
            name=case_in.name,
            description=case_in.description,
            owner_id=owner_id,
            owner_name=owner_name,
            assigned_user_ids=[]
        )
        inserted = self.repository.insert_one(case_data.model_dump())
        return Case(**inserted)

    def get_case(self, case_id: str, current_user: Optional[UserOut] = None) -> Optional[Case]:
        case_dict = self.repository.find_one({"case_id": case_id})
        if not case_dict:
            return None
        if not self.is_case_authorized(case_dict, current_user, allow_viewer=True):
            return None
        return Case(**case_dict)

    def get_all_cases(self, current_user: Optional[UserOut] = None) -> list[Case]:
        if not current_user or current_user.role == UserRole.ADMIN:
            query = {}
        elif current_user.role == UserRole.INVESTIGATOR:
            query = {
                "$or": [
                    {"owner_id": current_user.user_id},
                    {"assigned_user_ids": current_user.user_id}
                ]
            }
        elif current_user.role == UserRole.VIEWER:
            query = {"assigned_user_ids": current_user.user_id}
        else:
            query = {"owner_id": "none"}

        cases_list = self.repository.find_all(query)
        return [Case(**c) for c in cases_list]

    def update_case(self, case_id: str, case_in: CaseUpdate, current_user: Optional[UserOut] = None) -> Optional[Case]:
        case_dict = self.repository.find_one({"case_id": case_id})
        if not case_dict:
            return None
            
        # Viewers can never modify cases
        if current_user and current_user.role == UserRole.VIEWER:
            return None
            
        # Investigators can only modify their own cases
        if current_user and current_user.role == UserRole.INVESTIGATOR and case_dict.get("owner_id") != current_user.user_id:
            return None

        update_data = case_in.model_dump(exclude_unset=True)
        update_data["updated_at"] = datetime.utcnow()

        self.repository.update_one({"case_id": case_id}, update_data)
        updated_dict = self.repository.find_one({"case_id": case_id})
        return Case(**updated_dict) if updated_dict else None

    def delete_case(self, case_id: str, current_user: Optional[UserOut] = None) -> bool:
        case_dict = self.repository.find_one({"case_id": case_id})
        if not case_dict:
            return False

        # Only Admins and the original owner can delete a case
        if current_user and current_user.role != UserRole.ADMIN and case_dict.get("owner_id") != current_user.user_id:
            return False

        return self.repository.delete_one({"case_id": case_id})

    def assign_case_users(self, case_id: str, assigned_user_ids: list[str], current_user: Optional[UserOut] = None) -> Optional[Case]:
        case_dict = self.repository.find_one({"case_id": case_id})
        if not case_dict:
            return None

        # Only Admins and the owner can manage case assignments
        if current_user and current_user.role != UserRole.ADMIN and case_dict.get("owner_id") != current_user.user_id:
            return None

        self.repository.update_one(
            {"case_id": case_id},
            {
                "assigned_user_ids": assigned_user_ids,
                "updated_at": datetime.utcnow()
            }
        )
        updated_dict = self.repository.find_one({"case_id": case_id})
        return Case(**updated_dict) if updated_dict else None
