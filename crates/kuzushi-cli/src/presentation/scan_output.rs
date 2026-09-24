use super::scan_ci::{emit_scan_ci_error, emit_scan_ci_success};
use anyhow::Result;
use kuzushi_core::{run_dir, WorkspaceTarget};
use std::time::{Duration, Instant};

pub(crate) fn scan_result_or_report_ci_error(
    result: Result<serde_json::Value>,
    workspace: &WorkspaceTarget,
    run_id: &str,
    ci: bool,
    started: Instant,
    elapsed: Duration,
) -> Result<serde_json::Value> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            let error = scan_error_with_recovery(error, workspace, run_id);
            emit_scan_ci_error(ci, started, elapsed, &error);
            Err(error)
        }
    }
}

pub(crate) fn scan_error_with_recovery(
    error: anyhow::Error,
    workspace: &WorkspaceTarget,
    run_id: &str,
) -> anyhow::Error {
    let Some(recovery) = scan_failure_recovery(workspace, run_id) else {
        return error;
    };
    anyhow::anyhow!("{error:#}; {recovery}")
}

pub(crate) fn scan_failure_recovery(workspace: &WorkspaceTarget, run_id: &str) -> Option<String> {
    let summary = kuzushi_core::load_run_summary(workspace.root(), run_id).ok()?;
    if summary.status == "running" {
        return None;
    }
    Some(format!(
        "persisted run {run_id} at {}; from the target directory, inspect it with `kuzushi --target . runs show {run_id}`",
        run_dir(workspace.root(), run_id).display(),
    ))
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
        println!("{}", scan_json_output(workspace, result, &data));
    } else if let Some(android) = super::android_apk_report::format_android_apk_scan_plain(result) {
        print_plain_scan_body_and_footer(workspace, &data, &android);
    } else if let Some(output) = result.get("output").and_then(serde_json::Value::as_str) {
        // Tool/agent output passes through LLMs and scanned source —
        // strip ANSI/control bytes so a prompt-injected escape sequence
        // can't move the cursor, clear the screen, or spoof a fake prompt.
        print_plain_scan_body_and_footer(workspace, &data, output);
    } else {
        print!("{}", scan_plain_artifact_footer(workspace, &data));
    }
    Ok(())
}

fn print_plain_scan_body_and_footer(
    workspace: &WorkspaceTarget,
    data: &serde_json::Value,
    body: &str,
) {
    let safe_body = super::safe_text::sanitize_for_terminal(body);
    if !safe_body.is_empty() {
        print!("{safe_body}");
        if !safe_body.ends_with('\n') {
            println!();
        }
    }
    print!("{}", scan_plain_artifact_footer(workspace, data));
}

pub(crate) fn scan_result_data(result: &serde_json::Value) -> serde_json::Value {
    result
        .get("data")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}))
}

pub(crate) fn scan_json_output(
    workspace: &WorkspaceTarget,
    result: &serde_json::Value,
    data: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "ok": result.get("ok").cloned(),
        "status": result.get("status").cloned(),
        "summary": result.get("summary").cloned(),
        "warnings": result.get("warnings").cloned().unwrap_or_else(|| serde_json::json!([])),
        "errors": result.get("errors").cloned().unwrap_or_else(|| serde_json::json!([])),
        "runId": data.get("runId").cloned(),
        "target": data.get("target").cloned(),
        "findingsCount": data.get("findingsCount").cloned(),
        "observationsCount": data.get("observationsCount").cloned(),
        "costUsd": scan_cost_usd(result),
        "db": workspace.findings_db_path(),
        "mode": data.get("mode").cloned(),
        "whiteboxStatic": data.get("whiteboxStatic").cloned(),
        "triage": data.get("triage").cloned(),
    })
}

pub(crate) fn scan_plain_artifact_footer(
    workspace: &WorkspaceTarget,
    data: &serde_json::Value,
) -> String {
    let run_id = data
        .get("runId")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("latest");
    format!(
        "Artifacts: {}\nFindings DB: {}\nNext (from the target directory): kuzushi --target . runs show {}\n",
        run_dir(workspace.root(), run_id).display(),
        workspace.findings_db_path().display(),
        run_id,
    )
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
    fn scan_json_output_reports_the_same_rolled_up_cost() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let envelope = json!({
            "ok": true,
            "data": {
                "runId": "scan-cost-json",
                "agentic": { "costUsd": 0.17743 },
                "triage": { "costUsd": 0.00601 },
            }
        });
        let data = scan_result_data(&envelope);
        let output = scan_json_output(&workspace, &envelope, &data);

        let cost = output
            .get("costUsd")
            .and_then(serde_json::Value::as_f64)
            .unwrap();
        assert!((cost - scan_cost_usd(&envelope)).abs() < 1e-9, "got {cost}");
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

    #[test]
    fn scan_error_does_not_claim_recovery_when_failure_status_was_not_persisted() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let run_id = "scan-running-only";
        let running = kuzushi_core::RunSummary::running(
            run_id,
            "scan",
            Some("sast:scan".to_string()),
            workspace.root().display().to_string(),
        )
        .with_process_id(std::process::id());
        kuzushi_core::write_run_summary(workspace.root(), &running).unwrap();

        let error =
            scan_error_with_recovery(anyhow::anyhow!("dispatch failed"), &workspace, run_id)
                .to_string();

        assert_eq!(error, "dispatch failed");
        assert!(!error.contains("persisted run"));
    }

    #[test]
    fn scan_recovery_command_is_cross_platform_and_target_relative() {
        let temp = tempfile::Builder::new()
            .prefix("kuzushi recovery target ")
            .tempdir()
            .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let run_id = "scan-failed";
        let failed = kuzushi_core::RunSummary::running(
            run_id,
            "scan",
            Some("sast:scan".to_string()),
            workspace.root().display().to_string(),
        )
        .failed("scanner unavailable");
        kuzushi_core::write_run_summary(workspace.root(), &failed).unwrap();

        let recovery = scan_failure_recovery(&workspace, run_id).unwrap();

        assert!(
            recovery.contains("kuzushi --target . runs show scan-failed"),
            "{recovery}"
        );
        assert!(!recovery.contains("--target '"), "{recovery}");
        assert!(!recovery.contains("--target \""), "{recovery}");
    }
}
