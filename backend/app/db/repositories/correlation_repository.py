from app.db.repositories.base import BaseRepository

class CorrelationRepository(BaseRepository):
    def __init__(self):
        super().__init__("correlations")
