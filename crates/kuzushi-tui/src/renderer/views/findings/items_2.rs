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
    lines.push(divider("EVIDENCE", area.width));
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

pub(crate) fn finding_location(finding: &Finding) -> String {
    match finding.end_line {
        Some(end_line) if end_line > finding.start_line => {
            format!("{}:{}-{}", finding.file_path, finding.start_line, end_line)
        }
        _ => format!("{}:{}", finding.file_path, finding.start_line),
    }
}

pub(crate) fn finding_verdict_label(finding: &Finding) -> String {
    match finding
        .triage
        .as_ref()
        .map(|triage| triage.verdict.as_str())
    {
        Some("true_positive") => "tp",
        Some("false_positive") => "fp",
        Some("needs_review") => "review",
        Some("by_design") => "by-design",
        Some(other) => other,
        None => "untriaged",
    }
    .to_string()
}

pub(crate) fn finding_confidence_label(finding: &Finding) -> String {
    finding
        .triage
        .as_ref()
        .map(|triage| format!("{:.0}%", (triage.confidence.clamp(0.0, 1.0) * 100.0)))
        .unwrap_or_else(|| "-".to_string())
}

pub(crate) fn finding_cwe_label(finding: &Finding) -> String {
    extract_cwe(&finding.message)
        .or_else(|| extract_cwe(&finding.rule_id))
        .unwrap_or_else(|| "-".to_string())
}
