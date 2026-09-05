"""
Automated Pytest Test Suite for Power Side Channel Dpa Cpa.
Domain: Post-Quantum Cryptography & Hardware Security
Standard: NIST FIPS 203/204/205 / ISO/IEC 17825 Standards
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from agents.base import PHIGuard, AuditLogger, SecurityException, AuditTrail
from agents.models import SystemTaskPayload, UrgencyLevel, SystemIntegrityStatus
from agents.workers import InvariantQCWorker, SafetyEscalationWorker, ProtocolConformanceWorker
from agents.supervisor import SystemSupervisor
from cli import main


def test_phi_guard_enforcement():
    with pytest.raises(SecurityException):
        PHIGuard.assert_no_phi("Patient MRN-994827 blood culture positive for Staphylococcus")

    # Clean text passes
    PHIGuard.assert_no_phi("Analytical assay specimen KEY-001 optimal")


def test_phi_guard_redaction():
    """Test that PHI is properly redacted."""
    text_with_phi = "Patient John Doe MRN-994827 has phone 555-123-4567"
    redacted = PHIGuard.redact_phi(text_with_phi)
    assert "John Doe" not in redacted
    assert "994827" not in redacted
    assert "555-123-4567" not in redacted
    assert "[REDACTED_IDENTIFIER]" in redacted


def test_specialized_workers():
    # Worker 1: QC Invariant
    p1 = SystemTaskPayload(task_id="T1", target_identifier="KEY-01", primary_metric=35.0)
    alerts1 = InvariantQCWorker.evaluate(p1)
    assert len(alerts1) == 1
    assert alerts1[0].urgency == UrgencyLevel.ELEVATED

    # Worker 2: Safety
    p2 = SystemTaskPayload(task_id="T2", target_identifier="KEY-02", primary_metric=10.0, is_critical_flag=True)
    alerts2 = SafetyEscalationWorker.evaluate(p2)
    assert len(alerts2) == 1
    assert alerts2[0].urgency == UrgencyLevel.CRITICAL_STAT

    # Worker 3: Protocol Conformance
    p3 = SystemTaskPayload(task_id="T3", target_identifier="KEY-03", primary_metric=10.0, status_descriptor="DISCORDANT_ANOMALY")
    alerts3 = ProtocolConformanceWorker.evaluate(p3)
    assert len(alerts3) == 1


def test_supervisor_consensus_and_audit():
    supervisor = SystemSupervisor(model_provider="mock")
    payload = SystemTaskPayload(
        task_id="TASK-PROD-01",
        target_identifier="KEY-PROD-01",
        primary_metric=12.0,
        secondary_metric=4.0,
        status_descriptor="NOMINAL"
    )
    dossier = supervisor.process_task(payload)
    assert dossier.overall_urgency == UrgencyLevel.ROUTINE
    assert dossier.integrity_status == SystemIntegrityStatus.VALIDATED
    assert dossier.audit_hash != ""

    # Verify cryptographic audit trail
    assert AuditLogger.verify_integrity() is True

    # CLI tests
    assert main(["audit", "--task-id", "CLI-TEST-01"]) == 0
    assert main(["chat", "Explain", "specifications"]) == 0
    assert main(["verify-audit"]) == 0


def test_audit_trail_signature_verification():
    """Test that AuditTrail detects tampered entries via HMAC signature verification."""
    trail = AuditTrail(secret_key="test-secret-key-for-verification")
    trail.log("test-actor", "test-tier", "TEST_EVENT", {"data": "value1"})
    trail.log("test-actor", "test-tier", "TEST_EVENT", {"data": "value2"})

    # Trail should be valid initially
    assert trail.verify_integrity() is True

    # Tamper with an entry's payload_hash
    trail.logs[0]["payload_hash"] = "tampered_hash_value"

    # Verification should fail due to signature mismatch
    assert trail.verify_integrity() is False


def test_audit_trail_chain_linkage():
    """Test that AuditTrail detects broken chain linkage."""
    trail = AuditTrail(secret_key="test-secret-key-for-chain")
    trail.log("actor1", "tier1", "EVENT_1", {"k": "v1"})
    trail.log("actor2", "tier2", "EVENT_2", {"k": "v2"})

    assert trail.verify_integrity() is True

    # Break the chain by modifying prev_hash
    trail.logs[1]["prev_hash"] = "broken_link"

    assert trail.verify_integrity() is False


def test_audit_trail_empty():
    """Test that an empty audit trail is considered valid."""
    trail = AuditTrail(secret_key="test-secret-key-empty")
    assert trail.verify_integrity() is True
    assert len(trail.get_trail()) == 0


def test_audit_trail_phi_blocking():
    """Test that audit trail blocks PHI-containing entries."""
    trail = AuditTrail(secret_key="test-secret-key-phi")
    with pytest.raises(SecurityException):
        trail.log("actor", "tier", "EVENT", {"note": "Patient MRN-12345678"})
