use super::*;

pub(crate) fn replay_lines(app: &ShellApp, area: Rect, run_id: &str) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("REPLAY", area.width));
    lines.push(detail("run", run_id));
    let summary_path = run_artifact_path(app, run_id, "summary.json");
    let triage_path = run_artifact_path(app, run_id, "triage.jsonl");
    lines.push(run_artifact_detail("summary", &summary_path));
    lines.push(run_artifact_detail("triage", &triage_path));
    if !summary_path.exists() {
        lines.push(blank());
        lines.push(muted(
            "(run artefacts not on disk; check `show runs` for valid runIds)",
        ));
    }
    lines.extend(alias_reference_lines(app, area));
    lines
}

pub(crate) fn trace_lines(app: &ShellApp, area: Rect, run_id: &str) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider(&format!("TRACE · {run_id}"), area.width));
    let triage_path = run_artifact_path(app, run_id, "triage.jsonl");
    let verify_path = run_artifact_path(app, run_id, "verify.jsonl");
    let trace_path = run_artifact_path(app, run_id, "trace.jsonl");
    lines.push(detail("run", run_id));
    lines.push(run_artifact_detail("trace", &trace_path));
    lines.push(run_artifact_detail("triage", &triage_path));
    lines.push(run_artifact_detail("verify", &verify_path));

    // STEPS section per `design/mockups/trace.jsx::step` — one row per
    // agent step with kind-tinted column + label + latency + cost.
    let steps = parse_trace_jsonl(&trace_path);
    if steps.is_empty() {
        lines.push(blank());
        if !trace_path.exists() {
            lines.push(muted(
                "(no trace.jsonl on disk; trace artefacts ship with agentic / patch / verify runs)",
            ));
        } else {
            lines.push(muted("(trace.jsonl is empty)"));
        }
    } else {
        lines.push(blank());
        lines.push(divider("STEPS", area.width));
        for step in &steps {
            lines.push(trace_step_line(step, area.width));
        }
    }
    lines.extend(alias_reference_lines(app, area));
    lines
}

#[derive(Debug, Clone)]
pub(crate) struct TraceStep {
    pub(in crate::renderer::views) n: usize,
    pub(in crate::renderer::views) kind: String,
    pub(in crate::renderer::views) label: String,
    pub(in crate::renderer::views) latency_ms: Option<u64>,
    pub(in crate::renderer::views) cost_usd: Option<f64>,
    pub(in crate::renderer::views) module_id: Option<String>,
    pub(in crate::renderer::views) verb: Option<String>,
    pub(in crate::renderer::views) parent_step: Option<usize>,
    pub(in crate::renderer::views) severity: Option<String>,
    pub(in crate::renderer::views) started_at_ms: Option<u64>,
}

pub(crate) fn parse_trace_jsonl(path: &std::path::Path) -> Vec<TraceStep> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let n = value
            .get("n")
            .and_then(serde_json::Value::as_u64)
            .map(|n| n as usize)
            .unwrap_or(idx + 1);
        let kind = value
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("step")
            .to_string();
        let label = value
            .get("label")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("(no label)")
            .to_string();
        let latency_ms = value.get("latency_ms").and_then(serde_json::Value::as_u64);
        let cost_usd = value.get("cost_usd").and_then(serde_json::Value::as_f64);
        let module_id = value
            .get("module_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let verb = value
            .get("verb")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let parent_step = value
            .get("parent_step")
            .and_then(serde_json::Value::as_u64)
            .map(|n| n as usize);
        let severity = value
            .get("severity")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let started_at_ms = value.get("started_at_ms").and_then(serde_json::Value::as_u64);
        out.push(TraceStep {
            n,
            kind,
            label,
            latency_ms,
            cost_usd,
            module_id,
            verb,
            parent_step,
            severity,
            started_at_ms,
        });
    }
    out
}
