"""
Pytest configuration and fixtures for Threat Intel Tools tests.
"""

import pytest
from pathlib import Path


@pytest.fixture
def project_root():
    """Return the project root directory."""
    return Path(__file__).parent.parent


@pytest.fixture
def config_dir(project_root):
    """Return the config directory."""
    return project_root / 'config'


@pytest.fixture
def results_dir(project_root):
    """Return the results directory."""
    return project_root / 'results'


@pytest.fixture
def cache_dir(project_root):
    """Return the cache directory."""
    return project_root / 'cache'


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "security: mark test as a security validation test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )


def pytest_collection_modifyitems(config, items):
    """Automatically mark security tests."""
    for item in items:
        if "security" in str(item.fspath):
            item.add_marker(pytest.mark.security)
