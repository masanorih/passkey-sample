from app import app
import pytest


@pytest.fixture
def client():
    """client
    test_client() を返す fixture.
    """
    return app.test_client()
