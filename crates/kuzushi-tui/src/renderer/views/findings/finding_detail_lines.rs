use super::*;

pub(crate) fn finding_detail_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let Some(finding) = &app.selected_finding else {
        return findings_lines(app, area);
    };

    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(Line::from(vec![
        Span::styled(finding.severity.as_str(), theme::severity(finding.severity)),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(finding.title.clone(), theme::heading()),
    ]));
    lines.push(blank());
    if let Some(alias) = stable_finding_alias(&app.findings, &finding.fingerprint) {
        lines.push(detail("alias", &alias));
    }
    lines.push(detail(
        "location",
        &format!("{}:{}", finding.file_path, finding.start_line),
    ));
    lines.push(detail("rule", &finding.rule_id));
    lines.push(detail("tool", &finding.tool));
    lines.push(detail("fingerprint", &finding.fingerprint));
    lines.push(detail(
        "proof state",
        &fit(
            proof_state_label(finding.static_proof_state.clone()),
            value_width(area, 18),
        ),
    ));
    lines.push(detail(
        "runtime validation",
        &fit(
            &runtime_validation_label(finding.verification.as_ref()),
            value_width(area, 18),
        ),
    ));
    lines.push(blank());
    if !finding.evidence.is_empty() {
        lines.push(divider("STRUCTURED EVIDENCE", area.width));
        append_structured_evidence_lines(finding, area, &mut lines);
        lines.push(blank());
        lines.push(divider("MESSAGE", area.width));
    } else {
        lines.push(divider("EVIDENCE", area.width));
    }
    for line in finding.message.lines().take(8) {
        lines.push(indent(
            Line::raw(fit(line, area.width.saturating_sub(2) as usize)),
            2,
        ));
    }

    if let Some(triage) = &finding.triage {
        lines.push(blank());
        lines.push(divider("TRIAGE", area.width));
        lines.push(detail("verdict", triage.verdict.as_str()));
        lines.push(detail("confidence", &format!("{:.2}", triage.confidence)));
        lines.push(detail("rationale", &triage.rationale));
    }

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
    lines
}

fn append_structured_evidence_lines(finding: &Finding, area: Rect, lines: &mut Vec<Line<'static>>) {
    let header_width = area.width.saturating_sub(4) as usize;
    let detail_width = area.width.saturating_sub(6) as usize;
    for item in finding.evidence.iter().take(8) {
        let header = format!(
            "{} · conf {} · {}:{}",
            item.kind, item.confidence, item.file_path, item.line
        );
        lines.push(indent(muted(&fit(&header, header_width)), 2));
        if !item.snippet.trim().is_empty() {
            lines.push(indent(Line::raw(fit(&item.snippet, detail_width)), 4));
        }
        if !item.rationale.trim().is_empty() {
            lines.push(indent(muted(&fit(&item.rationale, detail_width)), 4));
        }
    }
}
