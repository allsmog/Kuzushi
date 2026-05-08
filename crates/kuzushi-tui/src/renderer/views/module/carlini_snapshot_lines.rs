use super::*;

pub(crate) fn carlini_snapshot_lines(
    report: &kuzushi_core::CarliniThreatHuntReport,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.push(transcript_line(
        "result",
        &format!(
            "carlini-threat-hunt: {} finding{} from {} actor{} ({} run{})",
            report.count,
            if report.count == 1 { "" } else { "s" },
            report.actors,
            if report.actors == 1 { "" } else { "s" },
            report.actor_runs,
            if report.actor_runs == 1 { "" } else { "s" },
        ),
        false,
    ));
    lines.push(transcript_line(
        "cost",
        &format!("cost ${:.4}", report.cost_usd),
        false,
    ));
    for finding in report.findings.iter().take(5) {
        lines.push(transcript_finding_line(
            finding.severity,
            &finding.rule_id,
            &finding.file_path,
            finding.start_line,
        ));
    }
    lines
}

pub(crate) fn agentic_sast_snapshot_lines(
    report: &kuzushi_core::AgenticSastReport,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.push(transcript_line(
        "result",
        &format!(
            "agentic-sast: {} finding{} under {}",
            report.count,
            if report.count == 1 { "" } else { "s" },
            report.target,
        ),
        false,
    ));
    lines.push(transcript_line(
        "cost",
        &format!("cost ${:.4}", report.cost_usd),
        false,
    ));
    for finding in report.findings.iter().take(5) {
        lines.push(transcript_finding_line(
            finding.severity,
            &finding.rule_id,
            &finding.file_path,
            finding.start_line,
        ));
    }
    lines
}

pub(in crate::renderer::views) struct ModuleRunSummary {
    pub(in crate::renderer::views) target: String,
    pub(in crate::renderer::views) stage: String,
    pub(in crate::renderer::views) findings: usize,
    pub(in crate::renderer::views) run: String,
    pub(in crate::renderer::views) active_stage: String,
    pub(in crate::renderer::views) scan_running: bool,
    pub(in crate::renderer::views) scan_done: bool,
    pub(in crate::renderer::views) has_scan: bool,
    pub(in crate::renderer::views) running_tool: Option<String>,
    pub(in crate::renderer::views) scan_error: Option<String>,
}
