from app.db.mongodb import db_helper

class BaseRepository:
    def __init__(self, collection_name: str):
        self.collection_name = collection_name

    @property
    def collection(self):
        # Resolve collection dynamically to support test database overrides at runtime
        return db_helper.db[self.collection_name]

    def find_one(self, query: dict) -> dict | None:
        return self.collection.find_one(query, {"_id": 0})

    def find_all(self, query: dict) -> list[dict]:
        return list(self.collection.find(query, {"_id": 0}))

    def insert_one(self, data: dict) -> dict:
        to_insert = data.copy()
        self.collection.insert_one(to_insert)
        # Avoid leaking internal MongoDB _id key back to schema validators
        to_insert.pop("_id", None)
        return to_insert

    def update_one(self, query: dict, update_data: dict) -> bool:
        result = self.collection.update_one(query, {"$set": update_data})
        return result.modified_count > 0

    def delete_one(self, query: dict) -> bool:
        result = self.collection.delete_one(query)
        return result.deleted_count > 0

    def delete_many(self, query: dict) -> int:
        result = self.collection.delete_many(query)
        return result.deleted_count
