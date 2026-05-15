use super::*;
use crate::ui_view_models::{
    selected_finding_detail_model, FindingDetailModel, FindingEvidenceRow, TriageSummaryModel,
};

pub(crate) fn finding_detail_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let Some(finding) = selected_finding_detail_model(app) else {
        return findings_lines(app, area);
    };

    let mut lines = context_strip(app, area);
    append_finding_title(&finding, &mut lines);
    append_finding_metadata(&finding, area, &mut lines);
    append_finding_evidence(&finding, area, &mut lines);
    append_triage_summary(&finding, area, &mut lines);
    append_finding_commands(area, &mut lines);
    lines
}

fn append_finding_title(finding: &FindingDetailModel, lines: &mut Vec<Line<'static>>) {
    lines.push(blank());
    lines.push(Line::from(vec![
        Span::styled(
            finding.severity_label.clone(),
            theme::severity(finding.severity),
        ),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(finding.title.clone(), theme::heading()),
    ]));
    lines.push(blank());
}

fn append_finding_metadata(
    finding: &FindingDetailModel,
    area: Rect,
    lines: &mut Vec<Line<'static>>,
) {
    if let Some(alias) = &finding.alias {
        lines.push(detail("alias", &alias));
    }
    lines.push(detail("location", &finding.location));
    lines.push(detail("rule", &finding.rule));
    lines.push(detail("tool", &finding.tool));
    lines.push(detail("fingerprint", &finding.fingerprint));
    lines.push(detail(
        "proof state",
        &fit(&finding.proof_state, value_width(area, 18)),
    ));
    lines.push(detail(
        "runtime verification",
        &fit(&finding.runtime_verification, value_width(area, 18)),
    ));
}

fn append_finding_evidence(
    finding: &FindingDetailModel,
    area: Rect,
    lines: &mut Vec<Line<'static>>,
) {
    lines.push(blank());
    if !finding.evidence.is_empty() {
        lines.push(divider("STRUCTURED EVIDENCE", area.width));
        append_structured_evidence_lines(&finding.evidence, area, lines);
        lines.push(blank());
        lines.push(divider("MESSAGE", area.width));
    } else {
        lines.push(divider("EVIDENCE", area.width));
    }
    for line in &finding.message_lines {
        lines.push(indent(
            Line::raw(fit(line, area.width.saturating_sub(2) as usize)),
            2,
        ));
    }
}

fn append_triage_summary(finding: &FindingDetailModel, area: Rect, lines: &mut Vec<Line<'static>>) {
    if let Some(triage) = &finding.triage {
        lines.push(blank());
        lines.push(divider("TRIAGE", area.width));
        append_triage_lines(triage, lines);
    }
}

fn append_triage_lines(triage: &TriageSummaryModel, lines: &mut Vec<Line<'static>>) {
    lines.push(detail("verdict", &triage.verdict));
    lines.push(detail("confidence", &triage.confidence));
    lines.push(detail("rationale", &triage.rationale));
}

fn append_finding_commands(area: Rect, lines: &mut Vec<Line<'static>>) {
    lines.push(blank());
    lines.push(command_list_line(
        &[
            "findings",
            "workspace export findings <path>.json",
            "kuzushi pr-comment",
            "back",
        ],
        area.width as usize,
    ));
}

fn append_structured_evidence_lines(
    evidence: &[FindingEvidenceRow],
    area: Rect,
    lines: &mut Vec<Line<'static>>,
) {
    let header_width = area.width.saturating_sub(4) as usize;
    let detail_width = area.width.saturating_sub(6) as usize;
    for item in evidence {
        lines.push(indent(muted(&fit(&item.header, header_width)), 2));
        if !item.snippet.trim().is_empty() {
            lines.push(indent(Line::raw(fit(&item.snippet, detail_width)), 4));
        }
        if !item.rationale.trim().is_empty() {
            lines.push(indent(muted(&fit(&item.rationale, detail_width)), 4));
        }
    }
}
