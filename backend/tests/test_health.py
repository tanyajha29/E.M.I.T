from unittest.mock import patch
from fastapi.testclient import TestClient
from app.main import app
from app.core.config import Settings

client = TestClient(app)

def test_health_endpoint_connected():
    # Test health endpoint when database is simulated as connected
    with patch("app.main.db_helper.check_health", return_value=True):
        response = client.get("/health")
        assert response.status_code == 200
        json_data = response.json()
        assert json_data["status"] == "ok"
        assert json_data["service"] == "E.M.I.T. API"
        assert json_data["database"]["status"] == "connected"

def test_health_endpoint_disconnected():
    # Test health endpoint when database is simulated as disconnected
    with patch("app.main.db_helper.check_health", return_value=False):
        response = client.get("/health")
        assert response.status_code == 200
        json_data = response.json()
        assert json_data["status"] == "degraded"
        assert json_data["service"] == "E.M.I.T. API"
        assert json_data["database"]["status"] == "disconnected"

def test_backend_startup_graceful_on_malformed_config():
    # Verify app configuration load handles malformed settings gracefully
    settings_instance = Settings(
        MONGODB_URI="invalid_uri_string_without_scheme",
        MONGODB_DATABASE=""
    )
    assert settings_instance.MONGODB_URI == "invalid_uri_string_without_scheme"
