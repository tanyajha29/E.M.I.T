from app.db.repositories.base import BaseRepository

class AttackNodeRepository(BaseRepository):
    def __init__(self):
        super().__init__("attack_nodes")

class AttackEdgeRepository(BaseRepository):
    def __init__(self):
        super().__init__("attack_edges")
