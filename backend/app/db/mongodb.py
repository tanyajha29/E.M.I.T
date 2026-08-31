import logging
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from app.core.config import settings

logger = logging.getLogger("emit.database")

class Database:
    def __init__(self):
        self._client = None
        self._db = None
        self._uri_override = None
        self._db_override = None

    def override_db(self, uri: str, name: str):
        """Allow test suites to redirect data access to a test database."""
        self.disconnect()
        self._uri_override = uri
        self._db_override = name

    def disconnect(self):
        """Close connection client and reset session state."""
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
        self._client = None
        self._db = None

    def connect(self):
        if self._client is None:
            try:
                uri = self._uri_override or settings.MONGODB_URI
                db_name = self._db_override or settings.MONGODB_DATABASE
                # serverSelectionTimeoutMS controls discovery timeout to fail fast
                self._client = MongoClient(
                    uri,
                    serverSelectionTimeoutMS=2000
                )
                self._db = self._client[db_name]
            except Exception as e:
                logger.error(f"Failed to initialize MongoDB client: {e}")
                self._client = None
                self._db = None

    @property
    def client(self) -> MongoClient:
        self.connect()
        return self._client

    @property
    def db(self):
        self.connect()
        return self._db

    def check_health(self) -> bool:
        try:
            self.connect()
            if self._client is None:
                return False
            # Ping database server to verify active connection
            self._client.admin.command("ping")
            return True
        except (ConnectionFailure, Exception) as e:
            logger.warning(f"Database health check failed: {e}")
            return False

# Reusable database helper instance
db_helper = Database()
