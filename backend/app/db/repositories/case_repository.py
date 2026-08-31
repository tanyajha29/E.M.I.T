from app.db.repositories.base import BaseRepository

class CaseRepository(BaseRepository):
    def __init__(self):
        super().__init__("cases")
