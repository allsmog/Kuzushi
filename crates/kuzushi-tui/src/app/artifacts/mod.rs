use super::*;
pub(crate) use super::*;

pub(super) fn short_label(text: &str, max: usize) -> String {
    let cleaned = text.replace('\n', " ");
    if cleaned.chars().count() <= max {
        cleaned
    } else {
        let mut out: String = cleaned.chars().take(max - 1).collect();
        out.push('…');
        out
    }
}

/// Write minimal run metadata so the runs ledger can list synthetic
/// agent / scan runs alongside real artefacts. Best-effort; silent on
/// failure.
pub fn write_run_summary(
    target: Option<&std::path::Path>,
    run_id: &str,
    status: &str,
    findings: Option<u64>,
    target_label: &str,
) {
    // Only write when an explicit workspace target is set — otherwise
    // synthetic agent runs would land in the cwd's .kuzushi/runs and
    // pollute test workspaces (cwd is `crates/<name>` during cargo test).
    let Some(target) = target else { return };
    let mut summary = kuzushi_core::RunSummary::running(
        run_id.to_string(),
        "shell",
        None,
        target_label.to_string(),
    )
    .with_findings(findings);
    summary.status = canonical_run_status(status).to_string();
    let _ = kuzushi_core::write_run_summary(target, &summary);
}

pub fn write_run_failure_handoff(
    target: Option<&std::path::Path>,
    run_id: &str,
    tool: &str,
    status: &str,
    error: &str,
) {
    let Some(target) = target else { return };
    let _ = kuzushi_core::run_artifacts::write_run_failures(
        target,
        run_id,
        tool,
        canonical_run_status(status),
        error,
        &[],
    );
}

fn canonical_run_status(status: &str) -> &'static str {
    match status.to_ascii_lowercase().as_str() {
        "complete" | "completed" | "ok" | "success" => "completed",
        "failed" | "error" => "failed",
        "partial" => "partial",
        "skipped" | "skip" => "skipped",
        "paused" | "cancelled" | "canceled" => "paused",
        "running" | "started" => "running",
        _ => "running",
    }
}

/// Append a single `TraceStep`-shaped JSON object to the trace.jsonl
/// for the given `run_id` under `<target>/.kuzushi/runs/<run_id>/`.
/// No-ops on any I/O error so a missing target dir or read-only mount
/// doesn't crash a worker — trace writes are observability, not a
/// correctness contract.  `kind` is the renderer's tint key:
/// `plan` / `tool` / `llm` / `critic` / `refused`.
pub fn append_trace_step(
    target: Option<&std::path::Path>,
    run_id: &str,
    n: usize,
    kind: &str,
    label: &str,
    latency_ms: Option<u64>,
    cost_usd: Option<f64>,
) {
    let Some(target) = target else { return };
    let step = kuzushi_core::RunTraceStep::new(n, kind.to_string(), label.to_string())
        .with_latency_ms(latency_ms)
        .with_cost_usd(cost_usd);
    let _ = kuzushi_core::append_run_trace_step(target, run_id, &step);
}

pub fn append_llm_trace_step(
    target: Option<&std::path::Path>,
    run_id: &str,
    n: usize,
    kind: &str,
    label: &str,
    latency_ms: Option<u64>,
    audit: &AgentCallAudit,
) {
    let Some(target) = target else { return };
    let step = kuzushi_core::RunTraceStep::new(n, kind.to_string(), label.to_string())
        .with_latency_ms(latency_ms)
        .with_cost_usd(audit.cost_usd)
        .with_model_metadata(&audit.model, &audit.provider, &audit.prompt_hash);
    let _ = kuzushi_core::append_run_trace_step(target, run_id, &step);
}
