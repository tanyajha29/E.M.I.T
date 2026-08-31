from app.db.repositories.base import BaseRepository

class IndicatorRepository(BaseRepository):
    def __init__(self):
        super().__init__("indicators")
