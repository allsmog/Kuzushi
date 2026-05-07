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

/// Write a minimal `summary.json` for `<target>/.kuzushi/runs/<run_id>/`
/// so the runs ledger can list synthetic agent / scan runs alongside
/// real artefacts.  Best-effort; silent on failure.
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
    summary.status = status.to_string();
    let _ = kuzushi_core::write_run_summary(target, &summary);
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
