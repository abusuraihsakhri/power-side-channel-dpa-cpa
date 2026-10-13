"""Regression tests for CSV parsing, secret-handling boundaries and CPA benchmarks."""
import csv
import math
import random

import pytest
from pydantic import ValidationError

from agents.base import AuditTrail, SecurityException
from agents.models import SystemTaskPayload
from agents.supervisor import SystemSupervisor
from cli import main as main_cli
from cpa_side_channel.cli import main as cpa_cli
from cpa_side_channel.performance_benchmark import AES_SBOX, PerformanceBenchmarkEngine


@pytest.mark.parametrize(
    "runner,status_field",
    [(main_cli, "overall_urgency"), (cpa_cli, "overall_status")],
)
def test_csv_batch_false_flag_is_not_truthy(tmp_path, runner, status_field):
    source = tmp_path / "input.csv"
    destination = tmp_path / "result.csv"
    with source.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=[
            "task_id", "target_identifier", "primary_metric", "secondary_metric",
            "status_descriptor", "is_critical_flag", status_field,
        ])
        writer.writeheader()
        for i, value in enumerate(["False", "0", "true", "YES"]):
            writer.writerow({
                "task_id": f"T{i}", "target_identifier": "KEY-DEMO",
                "primary_metric": 1, "secondary_metric": 1,
                "status_descriptor": "NOMINAL", "is_critical_flag": value,
                status_field: "prior-value",
            })
    assert runner(["batch", "-i", str(source), "-o", str(destination)]) == 0
    with destination.open(newline="", encoding="utf-8") as result:
        reader = csv.DictReader(result)
        assert reader.fieldnames.count(status_field) == 1
        records = list(reader)
    assert len(records) == 4
    assert "CRITICAL" not in records[0][status_field]
    assert "CRITICAL" not in records[1][status_field]
    assert "CRITICAL" in records[2][status_field]
    assert "CRITICAL" in records[3][status_field]


@pytest.mark.parametrize("runner", [main_cli, cpa_cli])
def test_csv_batch_rejects_invalid_boolean(tmp_path, runner):
    source = tmp_path / "input.csv"
    source.write_text(
        "task_id,target_identifier,primary_metric,secondary_metric,status_descriptor,is_critical_flag\\n"
        "T1,KEY-01,1,1,NOMINAL,sometimes\\n".replace("\\n", "\n"),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="is_critical_flag"):
        runner(["batch", "-i", str(source), "-o", str(tmp_path / "output.csv")])


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_model_rejects_nonfinite_metrics(value):
    with pytest.raises(ValidationError):
        SystemTaskPayload(task_id="T", target_identifier="KEY", primary_metric=value)
    with pytest.raises(ValidationError):
        SystemTaskPayload(task_id="T", target_identifier="KEY", primary_metric=1, secondary_metric=value)


def test_nested_metadata_is_screened_before_processing():
    supervisor = SystemSupervisor()
    payload = SystemTaskPayload(
        task_id="T", target_identifier="KEY", primary_metric=1,
        attributes={"nested": {"note": "MRN-123456"}},
    )
    with pytest.raises(SecurityException):
        supervisor.process_task(payload)


def test_audit_trail_getter_does_not_expose_mutable_internal_entries():
    trail = AuditTrail(secret_key="regression-secret")
    trail.log("actor", "tier", "EVENT", {"status": "ok"})
    extracted = trail.get_trail()
    extracted[0]["payload_hash"] = "modified"
    extracted.clear()
    assert len(trail.get_trail()) == 1
    assert trail.verify_integrity()


def test_key_rank_reports_true_key_not_winning_candidate(monkeypatch):
    benchmark = PerformanceBenchmarkEngine()
    plaintexts = [bytes([i]) + bytes(15) for i in range(32)]
    wrong_key = 0x55
    traces = [[AES_SBOX[i ^ wrong_key].bit_count() / 8.0] for i in range(32)]
    monkeypatch.setattr(benchmark, "generate_traces", lambda *args, **kwargs: (traces, plaintexts))
    result = benchmark.benchmark_cpa_convergence([32])[0]
    assert result.correct_key_recovered is False
    assert result.key_rank > 1


def test_trace_generator_does_not_reset_global_random_state():
    benchmark = PerformanceBenchmarkEngine()
    random.seed(90210)
    state_before = random.getstate()
    traces, plaintexts = benchmark.generate_traces(3, n_samples=1)
    assert len(traces) == len(plaintexts) == 3
    assert random.getstate() == state_before
