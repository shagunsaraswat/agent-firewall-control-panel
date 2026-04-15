"""Shared fixtures for Agent FirewallKit Python binding tests."""
import json
import os
from pathlib import Path


FIXTURES_DIR = Path(__file__).parent.parent.parent.parent / "tests" / "fixtures"


def load_golden_vectors():
    """Load shared witness golden vectors for cross-language parity."""
    path = FIXTURES_DIR / "witness_golden_vectors.json"
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {"vectors": []}
