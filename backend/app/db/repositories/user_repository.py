from app.db.repositories.base import BaseRepository

class UserRepository(BaseRepository):
    def __init__(self):
        super().__init__("users")

    def get_by_email(self, email: str) -> dict | None:
        return self.find_one({"email": email.strip().lower()})

    def get_by_id(self, user_id: str) -> dict | None:
        return self.find_one({"user_id": user_id})

    def create_user(self, user_dict: dict) -> dict:
        user_dict["email"] = user_dict["email"].strip().lower()
        return self.insert_one(user_dict)

    def list_all_users(self) -> list[dict]:
        return self.find_all({})

    def update_user(self, user_id: str, update_dict: dict) -> bool:
        return self.update_one({"user_id": user_id}, update_dict)
