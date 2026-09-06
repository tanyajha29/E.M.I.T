from datetime import datetime
from app.db.repositories.base import BaseRepository

class SessionRepository(BaseRepository):
    def __init__(self):
        super().__init__("sessions")

    def create_session(self, session_id: str, user_id: str, token: str, expires_at: datetime) -> dict:
        session_data = {
            "session_id": session_id,
            "user_id": user_id,
            "token": token,
            "created_at": datetime.utcnow(),
            "expires_at": expires_at,
            "is_revoked": False
        }
        return self.insert_one(session_data)

    def is_session_valid(self, session_id: str) -> bool:
        doc = self.find_one({"session_id": session_id})
        if not doc:
            return False
        if doc.get("is_revoked", False):
            return False
        expires_at = doc.get("expires_at")
        if expires_at and expires_at < datetime.utcnow():
            return False
        return True

    def revoke_session(self, session_id: str) -> bool:
        return self.update_one({"session_id": session_id}, {"is_revoked": True})

    def revoke_user_sessions(self, user_id: str) -> int:
        result = self.collection.update_many({"user_id": user_id}, {"$set": {"is_revoked": True}})
        return result.modified_count
