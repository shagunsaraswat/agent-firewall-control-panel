"""Smoke tests for the agentfirewall Python binding."""
import pytest


def test_import_agentfirewall():
    """Verify the native module can be imported."""
    try:
        import agentfirewall
        assert hasattr(agentfirewall, "PolicyEvaluator")
        assert hasattr(agentfirewall, "WitnessGuard")
    except ImportError:
        pytest.skip("agentfirewall not built; run maturin develop first")


def test_policy_evaluator_create():
    """Verify PolicyEvaluator can be instantiated."""
    try:
        from agentfirewall import PolicyEvaluator
        evaluator = PolicyEvaluator()
        assert evaluator is not None
    except ImportError:
        pytest.skip("agentfirewall not built")


def test_witness_guard_create():
    """Verify WitnessGuard can be instantiated."""
    try:
        from agentfirewall import WitnessGuard
        guard = WitnessGuard()
        assert guard is not None
    except ImportError:
        pytest.skip("agentfirewall not built")
