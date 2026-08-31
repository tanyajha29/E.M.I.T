from app.db.repositories.base import BaseRepository

class APKAnalysisRepository(BaseRepository):
    def __init__(self):
        super().__init__("apk_analyses")

class NetworkAnalysisRepository(BaseRepository):
    def __init__(self):
        super().__init__("network_analyses")
