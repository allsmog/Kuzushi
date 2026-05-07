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
    let runs_root = target.join(".kuzushi/runs");
    let dir = runs_root.join(run_id);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let mut summary = serde_json::Map::new();
    summary.insert("status".to_string(), serde_json::json!(status));
    if let Some(n) = findings {
        summary.insert("findings".to_string(), serde_json::json!(n));
    }
    summary.insert("target".to_string(), serde_json::json!(target_label));
    let bytes = match serde_json::to_vec_pretty(&serde_json::Value::Object(summary)) {
        Ok(bytes) => bytes,
        Err(_) => return,
    };
    let _ = std::fs::write(dir.join("summary.json"), bytes);
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
    let runs_root = target.join(".kuzushi/runs");
    let dir = runs_root.join(run_id);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("trace.jsonl");
    let mut entry = serde_json::Map::new();
    entry.insert("n".to_string(), serde_json::json!(n));
    entry.insert("kind".to_string(), serde_json::json!(kind));
    entry.insert("label".to_string(), serde_json::json!(label));
    if let Some(ms) = latency_ms {
        entry.insert("latency_ms".to_string(), serde_json::json!(ms));
    }
    if let Some(cost) = cost_usd {
        entry.insert("cost_usd".to_string(), serde_json::json!(cost));
    }
    let line = match serde_json::to_string(&serde_json::Value::Object(entry)) {
        Ok(line) => line,
        Err(_) => return,
    };
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{line}");
    }
}
