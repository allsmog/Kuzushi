use super::scan_ci::{emit_scan_ci_error, emit_scan_ci_success};
use anyhow::Result;
use kuzushi_core::WorkspaceTarget;
use std::time::{Duration, Instant};

pub(crate) fn scan_result_or_report_ci_error(
    result: Result<serde_json::Value>,
    ci: bool,
    started: Instant,
    elapsed: Duration,
) -> Result<serde_json::Value> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            emit_scan_ci_error(ci, started, elapsed, &error);
            Err(error)
        }
    }
}

pub(crate) fn emit_scan_output(
    workspace: &WorkspaceTarget,
    result: &serde_json::Value,
    json: bool,
    ci: bool,
    started: Instant,
    elapsed: Duration,
) -> Result<()> {
    let data = scan_result_data(result);
    if ci {
        emit_scan_ci_success(result, &data, started, elapsed);
        return Ok(());
    }
    if json {
        println!("{}", scan_json_output(workspace, &data));
    } else if let Some(output) = result.get("output").and_then(serde_json::Value::as_str) {
        // Tool/agent output passes through LLMs and scanned source —
        // strip ANSI/control bytes so a prompt-injected escape sequence
        // can't move the cursor, clear the screen, or spoof a fake prompt.
        println!("{}", super::safe_text::sanitize_for_terminal(output));
    }
    Ok(())
}

pub(crate) fn scan_result_data(result: &serde_json::Value) -> serde_json::Value {
    result
        .get("data")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}))
}

pub(crate) fn scan_json_output(
    workspace: &WorkspaceTarget,
    data: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "runId": data.get("runId").cloned(),
        "target": data.get("target").cloned(),
        "findingsCount": data.get("findingsCount").cloned(),
        "db": workspace.findings_db_path(),
        "mode": data.get("mode").cloned(),
        "whiteboxStatic": data.get("whiteboxStatic").cloned(),
        "triage": data.get("triage").cloned(),
    })
}

pub(crate) fn scan_findings_count(data: &serde_json::Value) -> u64 {
    data.get("findingsCount")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

pub(crate) fn scan_cost_usd(result: &serde_json::Value) -> f64 {
    if let Some(top) = result.get("costUsd").and_then(serde_json::Value::as_f64) {
        return top;
    }
    let data = match result.get("data") {
        Some(data) => data,
        None => return 0.0,
    };
    SCAN_COST_STAGES
        .iter()
        .filter_map(|stage| {
            data.get(stage)
                .and_then(|node| node.get("costUsd"))
                .and_then(serde_json::Value::as_f64)
        })
        .sum()
}

/// Stages that report their own `costUsd` inside `data.<stage>`. The CLI's
/// one-line `summary: … $X.XXXX` rolls these up because the scan envelope
/// has no top-level `costUsd` of its own.
const SCAN_COST_STAGES: &[&str] = &[
    "agentic",
    "carlini",
    "carliniThreatHunt",
    "fullModeMulti",
    "offenseReview",
    "systemsHunt",
    "taintIris",
    "taintIrisNext",
    "triage",
    "verify",
];

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scan_cost_usd_sums_per_stage_costs() {
        let envelope = json!({
            "ok": true,
            "data": {
                "agentic": { "costUsd": 0.17743, "count": 1 },
                "triage": { "costUsd": 0.00601, "tp": 2 },
                "taintIrisNext": { "costUsd": 0.0, "count": 0 },
            }
        });
        let total = scan_cost_usd(&envelope);
        assert!((total - 0.18344).abs() < 1e-6, "got {total}");
    }

    #[test]
    fn scan_cost_usd_prefers_top_level_when_present() {
        let envelope = json!({
            "ok": true,
            "costUsd": 0.5,
            "data": {
                "agentic": { "costUsd": 0.17743 },
            }
        });
        assert!((scan_cost_usd(&envelope) - 0.5).abs() < 1e-9);
    }

    #[test]
    fn scan_cost_usd_returns_zero_for_static_only_run() {
        let envelope = json!({
            "ok": true,
            "data": {
                "findingsCount": 41,
                "engines": ["semgrep", "secret-scan"],
            }
        });
        assert_eq!(scan_cost_usd(&envelope), 0.0);
    }
}
