from app.db.repositories.base import BaseRepository

class ReportRepository(BaseRepository):
    def __init__(self):
        super().__init__("reports")
