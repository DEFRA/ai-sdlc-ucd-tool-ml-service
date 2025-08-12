"""Test configuration for app tests."""

import os
from unittest.mock import AsyncMock, patch

import pytest

# Set test environment before importing settings
os.environ["ENVIRONMENT"] = "test"
os.environ["MONGO_URI"] = "mongodb://localhost:27017/test"
os.environ["MONGO_DATABASE"] = "test-db"
os.environ["PORT"] = "8086"


@pytest.fixture(autouse=True)
def mock_mongo_client():
    """Mock MongoDB client for all tests."""
    with patch("app.common.mongo.get_mongo_client") as mock_client:
        mock_async_client = AsyncMock()
        mock_async_client.close = AsyncMock()
        mock_client.return_value = mock_async_client
        yield mock_client
