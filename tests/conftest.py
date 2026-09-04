import os
import pytest
from database.db import init_db


@pytest.fixture(autouse=True)
def isolate_database(tmp_path, monkeypatch):
    """
    Ensure every test run operates against a clean, isolated temporary SQLite database.
    Prevents tests from polluting the production database with test domains or mock attack events.
    """
    test_db = tmp_path / "test_waf.db"
    monkeypatch.setenv("BASTION_DB_PATH", str(test_db))
    init_db()
    yield
