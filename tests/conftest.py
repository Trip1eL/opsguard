from pathlib import Path

import pytest


@pytest.fixture
def tmp_path() -> Path:
    """Use a workspace-local temp directory in restricted Windows sandboxes."""
    path = Path(__file__).parent / ".tmp"
    path.mkdir(exist_ok=True)
    return path
