use super::*;
pub(crate) use super::*;

/// Write minimal run metadata so the runs ledger can list synthetic shell
/// runs alongside real artefacts. Existing metadata is terminalized in place;
/// callers must not replace the running seed and lose its start/model/artifacts.
#[cfg(test)]
pub fn write_run_summary(
    target: Option<&std::path::Path>,
    run_id: &str,
    status: &str,
    findings: Option<u64>,
    target_label: &str,
) {
    // Only write when an explicit workspace target is set — otherwise
    // synthetic agent runs would land in the cwd's .kuzushi/v3/runs and
    // pollute test workspaces (cwd is `crates/<name>` during cargo test).
    let Some(target) = target else { return };
    let status = canonical_run_status(status);
    let seed = kuzushi_core::load_run_summary(target, run_id).unwrap_or_else(|_| {
        kuzushi_core::RunSummary::running(
            run_id.to_string(),
            "shell",
            None,
            target_label.to_string(),
        )
        .with_loaded_modules(
            kuzushi_core::ModuleRegistry::with_v2_builtins().loaded_module_specifiers(),
        )
    });
    let mut summary = terminalize_shell_summary(seed, status);
    if findings.is_some() {
        summary = summary.with_findings(findings);
    }
    let _ = kuzushi_core::write_run_summary(target, &summary);
}

#[cfg(test)]
fn terminalize_shell_summary(
    mut summary: kuzushi_core::RunSummary,
    status: &str,
) -> kuzushi_core::RunSummary {
    match status {
        "running" => summary.with_process_id(std::process::id()),
        "completed" => summary.complete(),
        "failed" => summary.failed("shell run failed"),
        "canceled" => summary.canceled("shell run canceled"),
        "interrupted" => summary.interrupted("shell run interrupted"),
        "skipped" => summary.skipped("shell run skipped"),
        "partial" | "paused" => {
            summary.status = status.to_string();
            summary
        }
        _ => summary,
    }
}

pub fn record_agent_run_started(
    target: Option<&std::path::Path>,
    run_id: &str,
    input: &serde_json::Value,
    model: String,
    config_hash: Option<String>,
    loaded_modules: Vec<String>,
) -> anyhow::Result<()> {
    let Some(target) = target else { return Ok(()) };
    kuzushi_core::run_artifacts::try_record_tool_run_started_with_reproducibility(
        agent_run_record(target, run_id),
        input,
        Some(model),
        config_hash,
        loaded_modules,
    )
}

pub fn record_agent_run_completed(
    target: Option<&std::path::Path>,
    run_id: &str,
    answer_chars: usize,
    latency_ms: Option<u64>,
    audit: &AgentCallAudit,
) -> anyhow::Result<()> {
    let Some(target) = target else { return Ok(()) };
    let cost = audit.settlement_cost();
    let result = serde_json::json!({
        "ok": true,
        "status": "completed",
        "summary": "agent:ask completed",
        "output": "agent answer recorded",
        "artifacts": [],
        "warnings": [],
        "errors": [],
        "costUsd": cost.exact_usd(),
        "observedCostUsd": incomplete_observed_cost(cost),
        "providerSpendUnresolved": !cost.is_complete(),
        "data": {
            "answerChars": answer_chars,
            "latencyMs": latency_ms,
            "callAttempted": audit.call_attempted,
        },
    });
    kuzushi_core::run_artifacts::try_record_tool_run_complete(
        agent_run_record(target, run_id),
        &result,
    )
}

pub fn record_agent_run_failed(
    target: Option<&std::path::Path>,
    run_id: &str,
    error: &str,
    audit: &AgentCallAudit,
) -> anyhow::Result<()> {
    let Some(target) = target else { return Ok(()) };
    kuzushi_core::run_artifacts::try_record_tool_run_failed(
        agent_run_record(target, run_id),
        error,
    )?;
    update_recorded_run_cost(target, run_id, audit.settlement_cost())
}

pub fn record_agent_run_canceled(
    target: Option<&std::path::Path>,
    run_id: &str,
    reason: &str,
    audit: &AgentCallAudit,
) -> anyhow::Result<()> {
    let Some(target) = target else { return Ok(()) };
    kuzushi_core::run_artifacts::try_record_tool_run_canceled(
        agent_run_record(target, run_id),
        reason,
    )?;
    update_recorded_run_cost(target, run_id, audit.settlement_cost())
}

fn agent_run_record<'a>(
    target: &'a std::path::Path,
    run_id: &'a str,
) -> kuzushi_core::run_artifacts::ToolRunRecord<'a> {
    kuzushi_core::run_artifacts::ToolRunRecord::new(target, run_id, "shell", "agent:ask")
}

fn update_recorded_run_cost(
    target: &std::path::Path,
    run_id: &str,
    cost: kuzushi_core::runtime::RuntimeCostReport,
) -> anyhow::Result<()> {
    let summary = kuzushi_core::load_run_summary(target, run_id)?;
    kuzushi_core::write_run_summary(target, &summary.with_cost_report(cost)).map(|_| ())
}

fn incomplete_observed_cost(cost: kuzushi_core::runtime::RuntimeCostReport) -> Option<f64> {
    (!cost.is_complete() && !cost.is_unavailable()).then_some(cost.observed_usd())
}

#[cfg(test)]
pub fn write_run_failure_handoff(
    target: Option<&std::path::Path>,
    run_id: &str,
    tool: &str,
    status: &str,
    error: &str,
) -> anyhow::Result<()> {
    let Some(target) = target else { return Ok(()) };
    kuzushi_core::run_artifacts::write_run_failures(
        target,
        run_id,
        tool,
        canonical_run_status(status),
        error,
        &[],
    )
    .map(|_| ())
}

#[cfg(test)]
pub fn append_run_status_event(
    target: Option<&std::path::Path>,
    run_id: &str,
    tool: &str,
    status: &str,
    message: impl Into<String>,
) -> anyhow::Result<()> {
    let Some(target) = target else { return Ok(()) };
    let event = kuzushi_core::run_artifacts::RunEvent::new(
        kuzushi_core::run_artifacts::next_run_event_number(target, run_id),
        "tool",
        canonical_run_status(status),
        message,
    )
    .with_tool(tool);
    kuzushi_core::run_artifacts::append_run_event(target, run_id, &event).map(|_| ())
}

#[cfg(test)]
fn canonical_run_status(status: &str) -> &'static str {
    match status.to_ascii_lowercase().as_str() {
        "complete" | "completed" => "completed",
        "failed" => "failed",
        "canceled" | "cancelled" => "canceled",
        "interrupted" => "interrupted",
        "partial" => "partial",
        "skipped" => "skipped",
        "paused" => "paused",
        "running" => "running",
        _ => "running",
    }
}

#[cfg(test)]
mod run_summary_pid_tests {
    use super::write_run_summary;

    #[test]
    fn running_shell_summary_carries_current_process_id() {
        let tmp = tempfile::tempdir().unwrap();
        write_run_summary(Some(tmp.path()), "shell-run-1", "running", None, "target");

        let summary = kuzushi_core::load_run_summary(tmp.path(), "shell-run-1").unwrap();

        assert_eq!(summary.status, "running");
        assert_eq!(summary.process_id, Some(std::process::id()));
    }

    #[test]
    fn completed_shell_summary_carries_no_process_id() {
        let tmp = tempfile::tempdir().unwrap();
        write_run_summary(
            Some(tmp.path()),
            "shell-run-2",
            "completed",
            Some(3),
            "target",
        );

        let summary = kuzushi_core::load_run_summary(tmp.path(), "shell-run-2").unwrap();

        assert_eq!(summary.status, "completed");
        assert_eq!(summary.process_id, None);
    }
}
