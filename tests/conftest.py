"""
conftest.py — Shared pytest fixtures.

Pytest automatically loads this file before any test runs.
Anything decorated with @pytest.fixture here is available
to every test file as a function argument.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="session")
def client():
    """
    A FastAPI test client that lets us call our endpoints in-process.

    'session' scope means the same client is reused across all tests —
    much faster than creating a new one per test, especially because
    Detoxify takes 5 seconds to load.
    """
    return TestClient(app)