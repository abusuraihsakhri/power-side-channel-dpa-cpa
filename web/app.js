"use strict";

const form = document.getElementById("audit-form");
const mode = document.getElementById("mode");
const output = document.getElementById("outputConsole");
const resultLabel = document.getElementById("result-label");
const description = document.getElementById("mode-description");
const button = document.getElementById("evaluate");
let completed = 0;

function readInput() {
  const primary = document.getElementById("primary_metric").valueAsNumber;
  const secondary = document.getElementById("secondary_metric").valueAsNumber;
  if (!Number.isFinite(primary) || !Number.isFinite(secondary)) {
    throw new Error("Metrics must be finite numbers.");
  }
  return {
    task_id: document.getElementById("task_id").value.trim(),
    target_identifier: document.getElementById("target_id").value.trim(),
    primary_metric: primary,
    secondary_metric: secondary,
    status_descriptor: document.getElementById("status_descriptor").value.trim(),
    is_critical_flag: document.getElementById("is_critical").checked
  };
}

function evaluateLocally(payload) {
  const alerts = [];
  const add = (origin_worker, urgency, summary) => {
    alerts.push({ origin_worker, urgency, summary });
  };
  if (payload.primary_metric > 25) {
    add("InvariantQCWorker", "ELEVATED_RISK", "Primary metric exceeds 25");
  }
  if (payload.is_critical_flag || payload.secondary_metric > 12) {
    add("SafetyEscalationWorker", payload.is_critical_flag ? "CRITICAL_STAT_PANIC" : "ELEVATED_RISK",
      "Critical flag set or secondary metric exceeds 12");
  }
  if (["DISCORDANT", "ANOMALY", "MUTANT", "VIOLATION", "FAIL", "REJECT"].some(
    word => payload.status_descriptor.toUpperCase().includes(word))) {
    add("ProtocolConformanceWorker", "ELEVATED_RISK", "Status descriptor indicates a flagged condition");
  }
  const critical = alerts.filter(alert => alert.urgency === "CRITICAL_STAT_PANIC").length;
  const urgency = critical ? "CRITICAL_STAT_PANIC" : alerts.length ? "ELEVATED_RISK" : "ROUTINE";
  return {
    mode: "LOCAL_DEMONSTRATION",
    no_server_audit: true,
    task_id: payload.task_id,
    target_identifier: payload.target_identifier,
    overall_urgency: urgency,
    integrity_status: critical ? "RECALIBRATION_REQUIRED" : alerts.length ? "DISCORDANT_ANOMALY" : "VALIDATED_OPTIMAL",
    total_alerts: alerts.length,
    critical_alerts_count: critical,
    alerts
  };
}

function updateMode() {
  description.textContent = mode.value === "local"
    ? "Local demonstration: calculations run entirely in this browser. No network requests or cryptographic audit signatures."
    : "Connected mode: POST /api/audit on this website's origin. Requires the separately running Python FastAPI server; failures are reported, never simulated.";
}
mode.addEventListener("change", updateMode);

form.addEventListener("submit", async event => {
  event.preventDefault();
  button.disabled = true;
  output.textContent = "Evaluating…";
  try {
    const payload = readInput();
    if (!payload.task_id || !payload.target_identifier || !payload.status_descriptor) {
      throw new Error("Task, target and status fields must not be empty.");
    }
    let result;
    if (mode.value === "local") {
      result = evaluateLocally(payload);
      resultLabel.textContent = "Local, deterministic rule evaluation; no HMAC signature generated.";
      document.getElementById("m-audit").textContent = "—";
    } else {
      const response = await fetch(new URL("../api/audit", window.location.href), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail ? JSON.stringify(body.detail) : "API returned HTTP " + response.status);
      result = body;
      resultLabel.textContent = "Result returned by the Python REST API.";
      const metrics = await fetch(new URL("../metrics", window.location.href));
      if (metrics.ok) {
        const summary = await metrics.json();
        document.getElementById("m-audit").textContent = String(summary.audit_blocks_total);
      }
    }
    completed += 1;
    document.getElementById("m-tasks").textContent = String(completed);
    document.getElementById("m-status").textContent = result.overall_urgency || "—";
    output.textContent = JSON.stringify(result, null, 2);
  } catch (error) {
    resultLabel.textContent = "Evaluation failed; no result was generated.";
    output.textContent = "Error: " + (error instanceof Error ? error.message : String(error));
  } finally {
    button.disabled = false;
  }
});
updateMode();
