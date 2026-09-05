import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from cpa_side_channel.models import FrontierPayload, ExecutionStatus
from cpa_side_channel.engine import FrontierDomainEngine
from cpa_side_channel.agents import HammingDistanceLeakageAgent, PearsonCorrelationTracerAgent, KeyCandidateRankerAgent, SideChannelCoordinator
from cpa_side_channel.cli import main
from cpa_side_channel.formal_verification import (
    FormalVerificationEngine, hamming_weight, hamming_distance, toggle_count,
    LeakageModel, VerificationResult
)


def test_sub_agents():
    a1 = HammingDistanceLeakageAgent()
    p1 = FrontierPayload("T1", "KEY-01", primary_metric=35.0, secondary_metric=4.0, status_descriptor="NOMINAL")
    alerts1 = a1.audit(p1)
    assert len(alerts1) == 1
    assert alerts1[0].status == ExecutionStatus.ELEVATED_RISK

    a2 = PearsonCorrelationTracerAgent()
    p2 = FrontierPayload("T2", "KEY-02", primary_metric=10.0, secondary_metric=15.0, status_descriptor="NOMINAL", is_critical_flag=True)
    alerts2 = a2.audit(p2)
    assert len(alerts2) == 1
    assert alerts2[0].status == ExecutionStatus.CRITICAL_INTERVENTION

    a3 = KeyCandidateRankerAgent()
    p3 = FrontierPayload("T3", "KEY-03", primary_metric=10.0, secondary_metric=4.0, status_descriptor="DISCORDANT_ANOMALY")
    alerts3 = a3.audit(p3)
    assert len(alerts3) == 1


def test_coordinator():
    coord = SideChannelCoordinator()
    p_nominal = FrontierPayload("T4", "KEY-04", primary_metric=12.0, secondary_metric=4.0, status_descriptor="NOMINAL")
    dossier = coord.process(p_nominal)
    assert dossier["overall_status"] == ExecutionStatus.NOMINAL.value
    assert dossier["total_alerts"] == 0

    ans = coord.query_supervisory_chat("What standard is applied?")
    assert "ISO/IEC 17825 Side-Channel Testing" in ans or "specifications" in ans


def test_cli():
    assert main(["audit", "--task-id", "CLI-01"]) == 0
    assert main(["chat", "What", "is", "the", "system", "status?"]) == 0


def test_engine_primary_parameter_boundary():
    """Test that primary parameter boundary detection works correctly."""
    # Within bounds
    result = FrontierDomainEngine.evaluate_primary_parameter(20.0)
    assert result is None

    # At boundary
    result = FrontierDomainEngine.evaluate_primary_parameter(25.0)
    assert result is None

    # Above boundary
    result = FrontierDomainEngine.evaluate_primary_parameter(25.1)
    assert result is not None
    assert "exceeds" in result["details"]


def test_engine_secondary_kinetics():
    """Test secondary kinetics evaluation."""
    # Within bounds, not critical
    result = FrontierDomainEngine.evaluate_secondary_kinetics(8.0, False)
    assert result is None

    # Above secondary bound
    result = FrontierDomainEngine.evaluate_secondary_kinetics(15.0, False)
    assert result is not None

    # Critical flag triggers alert regardless
    result = FrontierDomainEngine.evaluate_secondary_kinetics(5.0, True)
    assert result is not None


def test_engine_spec_conformance():
    """Test specification conformance audit."""
    # Nominal status passes
    result = FrontierDomainEngine.audit_specification_conformance("NOMINAL", {})
    assert result is None

    # Discordant status triggers alert
    result = FrontierDomainEngine.audit_specification_conformance("DISCORDANT", {})
    assert result is not None

    # Violation status triggers alert
    result = FrontierDomainEngine.audit_specification_conformance("VIOLATION", {})
    assert result is not None


def test_hamming_weight_function():
    """Test Hamming weight calculation."""
    assert hamming_weight(0x00) == 0
    assert hamming_weight(0xFF) == 8
    assert hamming_weight(0x55) == 4
    assert hamming_weight(0xAA) == 4
    assert hamming_weight(0x01) == 1
    assert hamming_weight(0x03) == 2


def test_hamming_distance_function():
    """Test Hamming distance calculation."""
    assert hamming_distance(0x00, 0x00) == 0
    assert hamming_distance(0x00, 0xFF) == 8
    assert hamming_distance(0xFF, 0xFF) == 0
    assert hamming_distance(0x55, 0xAA) == 8


def test_toggle_count_function():
    """Test toggle count calculation."""
    assert toggle_count(0x00, 0x00) == 0
    assert toggle_count(0x00, 0xFF) == 8
    assert toggle_count(0x0F, 0xF0) == 8


def test_formal_verification_hamming_weight():
    """Test formal verification of Hamming weight model."""
    engine = FormalVerificationEngine()
    proof = engine.verify_hamming_weight_model()
    assert proof.result == VerificationResult.PASS
    assert proof.test_vectors_passed == proof.test_vectors_total


def test_formal_verification_hamming_distance():
    """Test formal verification of Hamming distance model."""
    engine = FormalVerificationEngine()
    proof = engine.verify_hamming_distance_model()
    assert proof.result == VerificationResult.PASS
    assert proof.test_vectors_passed == proof.test_vectors_total


def test_formal_verification_pearson_correlation():
    """Test Pearson correlation verification."""
    engine = FormalVerificationEngine()
    proof = engine.verify_pearson_correlation()
    assert proof.result == VerificationResult.PASS
    assert proof.absolute_error < 0.001


def test_formal_verification_convergence():
    """Test convergence monotonicity verification."""
    engine = FormalVerificationEngine()
    proof = engine.verify_convergence_monotonicity()
    assert proof.result == VerificationResult.PASS
    assert proof.is_monotonic is True


def test_formal_verification_aes_sbox():
    """Test AES S-Box leakage verification."""
    engine = FormalVerificationEngine()
    result = engine.verify_aes_sbox_leakage(0x00, 0x2B, LeakageModel.HAMMING_WEIGHT)
    assert result["verification"] == "PASS"
    assert result["predicted_leakage"] >= 0
    assert result["predicted_leakage"] <= 8


def test_full_verification_suite():
    """Test the complete formal verification suite."""
    engine = FormalVerificationEngine()
    result = engine.full_verification_suite()
    assert result["overall_result"] == "PASS"
    assert result["hamming_weight_proof"]["result"] == "PASS"
    assert result["hamming_distance_proof"]["result"] == "PASS"
    assert result["correlation_proof"]["result"] == "PASS"
    assert result["convergence_proof"]["result"] == "PASS"
