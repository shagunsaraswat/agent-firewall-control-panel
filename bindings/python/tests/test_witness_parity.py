"""Cross-language witness canonicalization parity tests.

Uses shared golden vectors from tests/fixtures/witness_golden_vectors.json
to verify Python binding produces identical hashes to Rust core.
"""
import pytest
from conftest import load_golden_vectors


def test_witness_hash_parity():
    """Each golden vector must produce the same hash as Rust."""
    vectors = load_golden_vectors()
    if not vectors.get("vectors"):
        pytest.skip("No golden vectors found")
    
    try:
        from agentfirewall import WitnessGuard
    except ImportError:
        pytest.skip("agentfirewall not built")
    
    guard = WitnessGuard()
    for vec in vectors["vectors"]:
        result = guard.compute_hash(vec["input"])
        assert result == vec["expected_hash"], (
            f"Hash mismatch for vector {vec.get('name', 'unnamed')}: "
            f"got {result}, expected {vec['expected_hash']}"
        )
