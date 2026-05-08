use super::*;

pub(crate) fn runs_row(
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
pub(crate) enum PastRunStatus {
    Complete,
    Running,
    Partial,
    Paused,
    Failed,
    Unknown,
}

#[derive(Debug, Clone)]
pub(crate) struct PastRun {
    pub(in crate::renderer::views) run_id: String,
    pub(in crate::renderer::views) status_kind: PastRunStatus,
    pub(in crate::renderer::views) findings: Option<u64>,
    pub(in crate::renderer::views) target: String,
}

impl PastRun {
    pub(in crate::renderer::views) fn status_label(&self) -> &'static str {
        match self.status_kind {
            PastRunStatus::Complete => "complete",
            PastRunStatus::Running => "running",
            PastRunStatus::Partial => "partial",
            PastRunStatus::Paused => "paused",
            PastRunStatus::Failed => "failed",
            PastRunStatus::Unknown => "—",
        }
    }
}

pub(crate) fn collect_past_runs(runs_root: &std::path::Path) -> Vec<PastRun> {
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

pub(crate) fn parse_past_run_status(s: &str) -> PastRunStatus {
    match s.to_ascii_lowercase().as_str() {
        "complete" | "done" | "ok" | "success" => PastRunStatus::Complete,
        "running" | "started" => PastRunStatus::Running,
        "partial" => PastRunStatus::Partial,
        "paused" => PastRunStatus::Paused,
        "failed" | "error" => PastRunStatus::Failed,
        _ => PastRunStatus::Unknown,
    }
}
