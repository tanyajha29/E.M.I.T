from app.db.repositories.base import BaseRepository

class EvidenceRepository(BaseRepository):
    def __init__(self):
        super().__init__("evidence_files")
