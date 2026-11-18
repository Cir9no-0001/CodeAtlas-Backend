import os

# Settings() is built when app modules are imported, so the test configuration
# must be in place first. These are forced (not setdefault) so a developer's
# real .env or shell variables can never leak into a test run.
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SESSION_SECRET_KEY"] = "test-only-session-secret"
os.environ["ENVIRONMENT"] = "test"
os.environ["GITHUB_CLIENT_ID"] = "test-github-client-id"
os.environ["GITHUB_CLIENT_SECRET"] = "test-github-client-secret"
os.environ["GOOGLE_CLIENT_ID"] = "test-google-client-id"
os.environ["GOOGLE_CLIENT_SECRET"] = "test-google-client-secret"
os.environ["OAUTH_REDIRECT_BASE_URL"] = "http://localhost:8000"
os.environ["EXTENSION_OAUTH_REDIRECT_URL"] = "http://localhost:3000/oauth-complete"

import pytest  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.db.database import Base, get_db  # noqa: E402
from app.routers import auth as auth_module  # noqa: E402

TEST_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=engine)


class _FakeResponse:
    """Minimal stand-in for the httpx response the breach check expects."""

    def __init__(self, text: str = ""):
        self.text = text

    def raise_for_status(self):
        pass


@pytest.fixture(autouse=True)
def hibp(monkeypatch):
    """Mock the Have I Been Pwned range API so tests never touch the network.

    By default no password is reported as breached. A test can change the
    behaviour through the returned dict:

        hibp["text"] = "<SHA1 suffix>:42"   # report that password as breached
        hibp["error"] = httpx.ConnectError("down")   # simulate an outage
    """
    state = {"text": "", "error": None}

    def fake_get(*args, **kwargs):
        if state["error"] is not None:
            raise state["error"]
        return _FakeResponse(state["text"])

    monkeypatch.setattr(auth_module.httpx, "get", fake_get)
    return state


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """The limiter keeps in-memory counters for the whole process; clear them
    so one test's requests don't trigger 429s in another."""
    auth_module.limiter.reset()
    yield


@pytest.fixture()
def db_session():
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client(db_session):
    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()