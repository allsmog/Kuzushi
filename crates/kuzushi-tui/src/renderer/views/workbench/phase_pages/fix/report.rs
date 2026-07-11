use super::*;
use crate::ui_view_models::{FindingDetailModel, FixPhaseModel, SeverityCounts};

pub(super) fn breakdown_lines(model: &FixPhaseModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled(
        fit(&breakdown_summary(model, width), width),
        theme::primary(),
    )];
    lines.push(report_scope_line(model, width));
    lines.push(selected_risk_line(model.finding.as_ref(), width));
    lines
}

fn breakdown_summary(model: &FixPhaseModel, width: usize) -> String {
    if width < 80 {
        return format!(
            "{} · {} total · {} terminal · {} open",
            compact_severity_summary(model.findings.counts),
            model.findings.total,
            model.review.complete_count,
            model.review.open_count
        );
    }
    format!(
        "{} · {} findings · {} terminal · {} open",
        severity_summary(model.findings.counts),
        model.findings.total,
        model.review.complete_count,
        model.review.open_count
    )
}

fn severity_summary(counts: SeverityCounts) -> String {
    let mut parts = Vec::new();
    push_count(&mut parts, counts.critical, "critical");
    push_count(&mut parts, counts.high, "high");
    push_count(&mut parts, counts.medium, "medium");
    push_count(&mut parts, counts.low, "low");
    push_count(&mut parts, counts.info, "info");
    if parts.is_empty() {
        "no severity totals".to_string()
    } else {
        parts.join("  ")
    }
}

fn compact_severity_summary(counts: SeverityCounts) -> String {
    let mut parts = Vec::new();
    push_count(&mut parts, counts.critical, "C");
    push_count(&mut parts, counts.high, "H");
    push_count(&mut parts, counts.medium, "M");
    push_count(&mut parts, counts.low, "L");
    push_count(&mut parts, counts.info, "I");
    if parts.is_empty() {
        "0 severity".to_string()
    } else {
        parts.join(" · ")
    }
}

fn push_count(parts: &mut Vec<String>, count: usize, label: &str) {
    if count > 0 {
        parts.push(format!("{count} {label}"));
    }
}

fn report_scope_line(model: &FixPhaseModel, width: usize) -> Line<'static> {
    let report = &model.report;
    let text = if width < 80 {
        format!(
            "report {}/{} · preview only · no report written",
            report.format, report.completeness
        )
    } else {
        format!(
            "report {}/{} · preview only; no report written · {}/{} · ▸ {}",
            report.format,
            report.completeness,
            report.counts.included_findings,
            report.counts.total_findings,
            model.export_command,
        )
    };
    Line::styled(fit(&text, width), theme::muted())
}

fn selected_risk_line(finding: Option<&FindingDetailModel>, width: usize) -> Line<'static> {
    let Some(finding) = finding else {
        return Line::styled(
            fit(
                "◇ no selected finding · review the queue before patching",
                width,
            ),
            theme::muted(),
        );
    };
    let alias = finding.alias.as_deref().unwrap_or("selected");
    Line::from(vec![
        Span::styled(format!("◆ {alias}  "), theme::warn()),
        Span::styled(
            format!("{}  ", finding.severity_label.to_ascii_uppercase()),
            theme::severity_tone(finding.severity_tone),
        ),
        Span::styled(
            fit(&finding.title, width.saturating_sub(alias.len() + 14)),
            theme::heading(),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_summary_omits_zero_buckets_without_claiming_clean() {
        let counts = SeverityCounts {
            critical: 1,
            high: 2,
            low: 1,
            ..SeverityCounts::default()
        };

        assert_eq!(severity_summary(counts), "1 critical  2 high  1 low");
        assert_eq!(compact_severity_summary(counts), "1 C · 2 H · 1 L");
        assert_eq!(
            severity_summary(SeverityCounts::default()),
            "no severity totals"
        );
    }
}
