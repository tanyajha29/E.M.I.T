from app.db.repositories.base import BaseRepository

class ThreatIntelRepository(BaseRepository):
    def __init__(self):
        super().__init__("threat_intelligence")
