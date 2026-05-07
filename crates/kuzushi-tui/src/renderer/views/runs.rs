use super::*;

pub(in crate::renderer) fn runs_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("RUNS", area.width));
    let widths = [12usize, 14, 9, value_width(area, 40)];
    lines.push(aligned_header(
        &["runId", "status", "findings", "target"],
        &widths,
    ));

    // Active scan first.
    let mut emitted = 0usize;
    if let Some(scan) = &app.scan {
        let run_id = scan
            .run_id
            .as_deref()
            .map(short)
            .unwrap_or_else(|| "pending".to_string());
        let status_text = scan_status(scan);
        let status_style = if scan.error.is_some() {
            theme::danger()
        } else if scan.running {
            theme::warn()
        } else {
            theme::success()
        };
        lines.push(runs_row(
            &run_id,
            &status_text,
            status_style,
            &scan.findings_count.to_string(),
            &scan.target.display().to_string(),
            &widths,
        ));
        emitted += 1;
    }

    // Past runs from disk: `<target>/.kuzushi/runs/<runId>/`.  Read up to
    // 20 most recent dirs (alphabetical-ish since runIds embed timestamps).
    let runs_root = app
        .target
        .as_deref()
        .map(|t| t.join(".kuzushi/runs"))
        .unwrap_or_else(|| std::path::PathBuf::from(".kuzushi/runs"));
    let mut past_runs: Vec<PastRun> = collect_past_runs(&runs_root);
    past_runs.sort_by(|a, b| b.run_id.cmp(&a.run_id));
    let take = (area.height.saturating_sub(8) as usize).max(5).min(20);
    for past in past_runs.iter().take(take) {
        // Skip the run that's already shown as the active scan.
        if let Some(scan) = &app.scan {
            if scan.run_id.as_deref().map(short).as_deref() == Some(short(&past.run_id).as_str()) {
                continue;
            }
        }
        let style = match past.status_kind {
            PastRunStatus::Complete => theme::success(),
            PastRunStatus::Partial | PastRunStatus::Paused => theme::warn(),
            PastRunStatus::Failed => theme::danger(),
            PastRunStatus::Unknown => theme::muted(),
        };
        lines.push(runs_row(
            &short(&past.run_id),
            past.status_label(),
            style,
            &past
                .findings
                .map(|n| n.to_string())
                .unwrap_or_else(|| "—".to_string()),
            &past.target,
            &widths,
        ));
        emitted += 1;
    }

    if emitted == 0 {
        // Empty state mirrors `design/mockups/empty-states.jsx::panel`
        // for the runs ledger (`RUNS · empty`) — every dispatch writes
        // a run dir, so suggest the cheapest first run.
        lines.extend(empty_state_panel(
            "no runs persisted",
            &[
                "every dispatch writes a run dir under .kuzushi/runs/<id>/.",
                "this workspace has not run a module yet.",
            ],
            &[
                ("scan", "first run will land at .kuzushi/runs/<id>/"),
                ("use context", "cheapest first run · indexes the workspace"),
            ],
        ));
    } else {
        lines.push(blank());
        lines.push(command_list_line(
            &["replay <runId>", "trace <runId>", "findings", "back"],
            area.width as usize,
        ));
    }
    lines
}

pub(in crate::renderer) fn runs_row(
    run_id: &str,
    status: &str,
    status_style: Style,
    findings: &str,
    target: &str,
    widths: &[usize; 4],
) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{}  ", pad(run_id, widths[0])), theme::accent()),
        Span::styled(
            format!("{}  ", pad(&fit(status, widths[1]), widths[1])),
            status_style,
        ),
        Span::styled(format!("{}  ", pad(findings, widths[2])), theme::primary()),
        Span::styled(
            format!("{}  ", pad(&fit(target, widths[3]), widths[3])),
            theme::muted(),
        ),
    ])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::renderer) enum PastRunStatus {
    Complete,
    Partial,
    Paused,
    Failed,
    Unknown,
}

#[derive(Debug, Clone)]
pub(in crate::renderer) struct PastRun {
    run_id: String,
    status_kind: PastRunStatus,
    findings: Option<u64>,
    target: String,
}

impl PastRun {
    fn status_label(&self) -> &'static str {
        match self.status_kind {
            PastRunStatus::Complete => "complete",
            PastRunStatus::Partial => "partial",
            PastRunStatus::Paused => "paused",
            PastRunStatus::Failed => "failed",
            PastRunStatus::Unknown => "—",
        }
    }
}

/// Walk `<target>/.kuzushi/runs/` and parse each subdir's optional
/// `summary.json` for status/findings/target.  Missing or unreadable
/// summaries fall back to the run-id directory name + "unknown" status.
pub(in crate::renderer) fn collect_past_runs(runs_root: &std::path::Path) -> Vec<PastRun> {
    let Ok(entries) = std::fs::read_dir(runs_root) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_dir() {
            continue;
        }
        let run_id = entry.file_name().to_string_lossy().to_string();
        let summary_path = entry.path().join("summary.json");
        let (status_kind, findings, target) = if let Ok(bytes) = std::fs::read(&summary_path) {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                let status = value
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .map(parse_past_run_status)
                    .unwrap_or(PastRunStatus::Unknown);
                let findings = value.get("findings").and_then(serde_json::Value::as_u64);
                let target = value
                    .get("target")
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string)
                    .unwrap_or_default();
                (status, findings, target)
            } else {
                (PastRunStatus::Unknown, None, String::new())
            }
        } else {
            (PastRunStatus::Unknown, None, String::new())
        };
        out.push(PastRun {
            run_id,
            status_kind,
            findings,
            target,
        });
    }
    out
}

pub(in crate::renderer) fn parse_past_run_status(s: &str) -> PastRunStatus {
    match s.to_ascii_lowercase().as_str() {
        "complete" | "done" | "ok" | "success" => PastRunStatus::Complete,
        "partial" => PastRunStatus::Partial,
        "paused" => PastRunStatus::Paused,
        "failed" | "error" => PastRunStatus::Failed,
        _ => PastRunStatus::Unknown,
    }
}

pub(in crate::renderer) fn replay_lines(
    app: &ShellApp,
    area: Rect,
    run_id: &str,
) -> Vec<Line<'static>> {
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

pub(in crate::renderer) fn trace_lines(
    app: &ShellApp,
    area: Rect,
    run_id: &str,
) -> Vec<Line<'static>> {
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
pub(in crate::renderer) struct TraceStep {
    n: usize,
    kind: String,
    label: String,
    latency_ms: Option<u64>,
    cost_usd: Option<f64>,
}

/// Parse a `trace.jsonl` artefact into typed steps.  Each line is a
/// JSON object with at minimum a `kind` (string) and `label` (string);
/// `n`, `latency_ms`, `cost_usd` are optional and default sensibly.
pub(in crate::renderer) fn parse_trace_jsonl(path: &std::path::Path) -> Vec<TraceStep> {
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
        out.push(TraceStep {
            n,
            kind,
            label,
            latency_ms,
            cost_usd,
        });
    }
    out
}

pub(in crate::renderer) fn trace_step_line(step: &TraceStep, width: u16) -> Line<'static> {
    let kind_style = match step.kind.as_str() {
        "plan" => theme::label(),
        "tool" => theme::success(),
        "llm" => theme::accent(),
        "refused" => theme::danger(),
        "critic" => theme::warn(),
        _ => theme::muted(),
    };
    let latency = step
        .latency_ms
        .map(|ms| {
            if ms >= 1000 {
                format!("{:.1}s", ms as f64 / 1000.0)
            } else {
                format!("{ms}ms")
            }
        })
        .unwrap_or_else(|| "—".to_string());
    let cost = step
        .cost_usd
        .map(|c| format!("${c:.4}"))
        .unwrap_or_else(|| "—".to_string());
    let label_budget = (width as usize).saturating_sub(28).max(20);
    Line::from(vec![
        Span::raw(" "),
        Span::styled(format!("{:>3} ", step.n), theme::subtle()),
        Span::styled(format!("{:8}", step.kind), kind_style),
        Span::raw(" "),
        Span::styled(fit(&step.label, label_budget), theme::primary()),
        Span::raw("  "),
        Span::styled(format!("{:>7}", latency), theme::muted()),
        Span::raw("  "),
        Span::styled(cost, theme::muted()),
    ])
}

pub(in crate::renderer) fn run_artifact_path(
    app: &ShellApp,
    run_id: &str,
    leaf: &str,
) -> std::path::PathBuf {
    let runs_root = app
        .target
        .as_deref()
        .map(|target| target.join(".kuzushi/runs"))
        .unwrap_or_else(|| std::path::PathBuf::from(".kuzushi/runs"));
    runs_root.join(run_id).join(leaf)
}

pub(in crate::renderer) fn run_artifact_detail(
    label: &str,
    path: &std::path::Path,
) -> Line<'static> {
    let display = path.display().to_string();
    let suffix = if path.exists() { "" } else { " (missing)" };
    detail(label, &format!("{display}{suffix}"))
}

pub(in crate::renderer) fn alias_reference_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let aliases = sorted_finding_aliases(&app.findings);
    lines.push(blank());
    if aliases.is_empty() {
        lines.push(muted("aliases: load findings first with findings"));
        return lines;
    }
    lines.push(divider("ALIASES", area.width));
    for (alias, finding) in aliases.into_iter().take(3) {
        lines.push(detail(
            &alias,
            &format!("{} {}", short(&finding.fingerprint), finding.title),
        ));
    }
    lines
}
