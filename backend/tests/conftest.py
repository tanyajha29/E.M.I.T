import pytest
from datetime import datetime
from app.core.config import settings
from app.db.mongodb import db_helper
from app.main import app
from app.core.security import get_current_user
from app.schemas.user import UserOut, UserRole

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    # Redirect all repository queries to the isolated test database
    db_helper.override_db(settings.MONGODB_TEST_URI, settings.MONGODB_TEST_DATABASE)
    db_helper.connect()
    try:
        db_helper.client.admin.command("ping")
    except Exception as e:
        pytest.fail(f"Could not connect to MongoDB test instance at {settings.MONGODB_TEST_URI}: {e}")
    
    yield
    
    # Session cleanup: drop the test database completely to avoid residue pollution
    if db_helper.client is not None:
        db_helper.client.drop_database(settings.MONGODB_TEST_DATABASE)
        db_helper.disconnect()

@pytest.fixture(autouse=True)
def clean_collections():
    # Clear all documents before each test case to guarantee complete isolation
    db = db_helper.db
    if db is not None:
        for col_name in db.list_collection_names():
            if not col_name.startswith("system."):
                db[col_name].delete_many({})
    yield

@pytest.fixture(autouse=True)
def default_test_auth(request):
    # Skip default override if test explicitly opts out via mark
    if "no_auth_override" in request.keywords:
        app.dependency_overrides.pop(get_current_user, None)
        yield
        return

    default_user = UserOut(
        user_id="test-investigator-001",
        email="test.investigator@emit.local",
        full_name="Default Test Investigator",
        role=UserRole.INVESTIGATOR,
        badge_id="EMIT-TEST-0001",
        is_active=True,
        created_at=datetime.utcnow()
    )
    app.dependency_overrides[get_current_user] = lambda: default_user
    yield
    app.dependency_overrides.pop(get_current_user, None)
