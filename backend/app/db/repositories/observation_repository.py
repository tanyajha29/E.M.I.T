from app.db.repositories.base import BaseRepository

class ObservationRepository(BaseRepository):
    def __init__(self):
        super().__init__("observations")
