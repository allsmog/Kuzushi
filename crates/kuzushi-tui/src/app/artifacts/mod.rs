use super::*;
pub(crate) use super::*;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

pub(super) fn short_label(text: &str, max: usize) -> String {
    let cleaned = text.replace('\n', " ");
    if UnicodeWidthStr::width(cleaned.as_str()) <= max {
        cleaned
    } else if max == 0 {
        String::new()
    } else {
        let mut out = take_display_columns(&cleaned, max.saturating_sub(1));
        out.push('…');
        out
    }
}

fn take_display_columns(value: &str, max: usize) -> String {
    let mut width = 0usize;
    let mut out = String::new();
    for ch in value.chars() {
        let next = width + UnicodeWidthChar::width(ch).unwrap_or(0);
        if next > max {
            break;
        }
        out.push(ch);
        width = next;
    }
    out
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
    // synthetic agent runs would land in the cwd's .kuzushi/v3/runs and
    // pollute test workspaces (cwd is `crates/<name>` during cargo test).
    let Some(target) = target else { return };
    let mut summary = kuzushi_core::RunSummary::running(
        run_id.to_string(),
        "shell",
        None,
        target_label.to_string(),
    )
    .with_findings(findings)
    .with_loaded_modules(
        kuzushi_core::ModuleRegistry::with_v2_builtins().loaded_module_specifiers(),
    );
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

pub fn append_run_status_event(
    target: Option<&std::path::Path>,
    run_id: &str,
    tool: &str,
    status: &str,
    message: impl Into<String>,
) {
    let Some(target) = target else { return };
    let event = kuzushi_core::run_artifacts::RunEvent::new(
        kuzushi_core::run_artifacts::next_run_event_number(target, run_id),
        "tool",
        canonical_run_status(status),
        message,
    )
    .with_tool(tool);
    let _ = kuzushi_core::run_artifacts::append_run_event(target, run_id, &event);
}

fn canonical_run_status(status: &str) -> &'static str {
    match status.to_ascii_lowercase().as_str() {
        "complete" | "completed" => "completed",
        "failed" => "failed",
        "partial" => "partial",
        "skipped" => "skipped",
        "paused" => "paused",
        "running" => "running",
        _ => "running",
    }
}

/// Append a single `TraceStep`-shaped JSON object to the trace.jsonl
/// for the given `run_id` under `<target>/.kuzushi/v3/runs/<run_id>/`.
/// No-ops on any I/O error so a missing target dir or read-only mount
/// doesn't crash a worker — trace writes are observability, not a
/// correctness contract.  `kind` is the renderer's tint key:
/// `plan` / `tool` / `llm` / `critic` / `refused`.
pub fn append_trace_step(
    target: Option<&std::path::Path>,
    run_id: &str,
    kind: &str,
    label: &str,
    latency_ms: Option<u64>,
    cost_usd: Option<f64>,
) {
    let Some(target) = target else { return };
    let step = kuzushi_core::RunTraceStep::new(0, kind.to_string(), label.to_string())
        .with_latency_ms(latency_ms)
        .with_cost_usd(cost_usd);
    let _ =
        kuzushi_core::run_artifacts::append_run_trace_step_with_next_number(target, run_id, &step);
}

pub fn append_llm_trace_step(
    target: Option<&std::path::Path>,
    run_id: &str,
    kind: &str,
    label: &str,
    latency_ms: Option<u64>,
    audit: &AgentCallAudit,
) {
    let Some(target) = target else { return };
    let step = kuzushi_core::RunTraceStep::new(0, kind.to_string(), label.to_string())
        .with_latency_ms(latency_ms)
        .with_cost_usd(audit.cost_usd)
        .with_model_metadata(&audit.model, &audit.provider, &audit.prompt_hash);
    let _ =
        kuzushi_core::run_artifacts::append_run_trace_step_with_next_number(target, run_id, &step);
}
