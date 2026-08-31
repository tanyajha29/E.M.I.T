from app.db.repositories.base import BaseRepository

class RiskRepository(BaseRepository):
    def __init__(self):
        super().__init__("risk_assessments")
