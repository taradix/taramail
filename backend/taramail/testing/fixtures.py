"""Testing fixtures."""

import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from taramail.api import app as _api_app
from taramail.deps import (
    get_db,
    get_memcached,
    get_queue,
    get_store,
)
from taramail.exporter import app as _exporter_app


@pytest.fixture
def api_app(db_session, memcached_store, redis_queue, redis_store):
    """API testing app."""
    _api_app.dependency_overrides[get_db] = lambda: db_session
    _api_app.dependency_overrides[get_memcached] = lambda: memcached_store
    _api_app.dependency_overrides[get_queue] = lambda: redis_queue
    _api_app.dependency_overrides[get_store] = lambda: redis_store

    url = db_session.bind.engine.url
    env = {
        "DBDRIVER": url.drivername,
        "DBNAME": url.database,
    }

    with patch.dict(os.environ, env), TestClient(_api_app) as client:
        yield client


@pytest.fixture
def exporter_app(db_session):
    """Exporter testing app."""
    _exporter_app.dependency_overrides[get_db] = lambda: db_session

    url = db_session.bind.engine.url
    env = {
        "DBDRIVER": url.drivername,
        "DBNAME": url.database,
    }

    with patch.dict(os.environ, env), TestClient(_exporter_app) as client:
        yield client
