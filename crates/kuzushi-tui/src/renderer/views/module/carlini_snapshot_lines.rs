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
            plural_suffix(report.count),
            report.actors,
            plural_suffix(report.actors),
            report.actor_runs,
            plural_suffix(report.actor_runs),
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
            plural_suffix(report.count),
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

fn plural_suffix(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}
