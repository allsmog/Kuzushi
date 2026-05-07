use super::*;

pub(in crate::renderer) fn findings_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    // Filter chip row, mirroring `design/mockups/findings.jsx::chip`:
    //   filters [all:38]  critical:5  high:11  medium:14  low:8
    // Active chip wears `[label:n]` brackets in c-accent; inactive chips
    // drop the brackets and render in c-muted with the count after the
    // colon. Counts come from the persisted finding set so operators can
    // size the filter buckets at a glance.
    let counts = SeverityCounts::from_findings(&app.findings);
    let total = app.findings.len();
    let mut chip_spans: Vec<Span<'static>> = Vec::new();
    chip_spans.push(Span::styled("filters ", theme::label()));
    chip_spans.push(Span::styled(format!("[all:{total}]"), theme::accent()));
    for (label, n, style) in [
        (
            "critical",
            counts.critical,
            theme::severity(Severity::Critical),
        ),
        ("high", counts.high, theme::severity(Severity::High)),
        ("medium", counts.medium, theme::severity(Severity::Medium)),
        ("low", counts.low, theme::severity(Severity::Low)),
    ] {
        chip_spans.push(Span::raw("  "));
        chip_spans.push(Span::styled(format!("{label}:{n}"), style));
    }
    lines.push(Line::from(chip_spans));
    lines.push(blank());

    if app.findings.is_empty() {
        // Empty state matches `design/mockups/empty-states.jsx::panel`:
        //   divider with `· empty` suffix · ∅ glyph + label · explanations
        //   · blank · CTA rows with `▸` warn glyph + accent command +
        //   muted blurb.
        let hint = if app.context_view.exists {
            "scan runs configured scanners against the active target."
        } else {
            "scan dispatches the umbrella scanner once context-snapshot exists."
        };
        let context_cta = if app.context_view.exists {
            None
        } else {
            Some(("context build", "build the snapshot first if you have time"))
        };
        lines.push(divider("FINDINGS · empty", area.width));
        lines.extend(empty_state_panel(
            "no findings yet",
            &[
                "kuzushi keeps the ledger in .kuzushi/v2/findings.sqlite3.",
                "nothing has been promoted on this workspace.",
            ],
            &[Some(("scan", hint)), context_cta]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>(),
        ));
        return lines;
    }

    let triaged = app.findings.iter().filter(|f| f.triage.is_some()).count();
    let pending = app.findings.len().saturating_sub(triaged);
    lines.push(section_header_line(
        &format!(
            "FINDINGS · {} · {triaged} triaged · {pending} pending",
            app.findings.len()
        ),
        area.width,
    ));

    let aliases = sorted_finding_aliases(&app.findings);
    let cursor = app.findings_cursor.min(aliases.len().saturating_sub(1));
    let mut body = Vec::new();
    for (index, (alias, finding)) in aliases.into_iter().enumerate() {
        let selected = app
            .selected_finding
            .as_ref()
            .is_some_and(|selected| selected.fingerprint.as_str() == finding.fingerprint.as_str());
        let cursor_row = app.findings_cursor == index;
        let marker = if cursor_row {
            "▌ "
        } else if selected {
            "* "
        } else {
            "  "
        };
        let marker_style = if cursor_row {
            theme::accent()
        } else if selected {
            theme::warn()
        } else {
            theme::subtle()
        };

        // Row 1: marker · alias · severity chip · title · location.
        // At narrow widths (<100 cols), location moves to row 2 so the title
        // doesn't get truncated to nothing.
        let alias_w = 8;
        let sev_w = 9;
        let prefix_used = 2 + alias_w + 2 + sev_w;
        let total = (area.width as usize).saturating_sub(prefix_used);
        let location = finding_location(&finding);
        let wide = area.width >= 100;
        let location_w = if wide {
            location.chars().count().min(total.saturating_sub(2)).max(8)
        } else {
            0
        };
        let name_w = if wide {
            total.saturating_sub(location_w + 2).max(12)
        } else {
            total.max(12)
        };
        let mut row1 = vec![
            Span::styled(marker, marker_style),
            Span::styled(pad(&alias, alias_w), theme::accent()),
            Span::raw("  "),
            Span::styled(
                pad(&finding.severity.as_str().to_uppercase(), sev_w),
                theme::severity(finding.severity),
            ),
            Span::styled(pad(&fit(&finding.title, name_w), name_w), theme::primary()),
        ];
        if wide {
            row1.push(Span::raw("  "));
            row1.push(Span::styled(fit(&location, location_w), theme::muted()));
        }
        body.push(Line::from(row1));

        // Row 2: indented muted detail (location at narrow widths +
        // verdict · conf · cwe · source · evidence).
        let verdict = finding_verdict_label(&finding);
        let conf = finding_confidence_label(&finding);
        let cwe = finding_cwe_label(&finding);
        let source = finding_source_label(&finding);
        let evidence = finding_evidence_preview(&finding);
        if wide {
            // Single indented detail line.
            let detail = format!("{verdict} · conf {conf} · {cwe} · {source} · {evidence}");
            body.push(indent(
                muted(&fit(&detail, area.width.saturating_sub(4) as usize)),
                4,
            ));
        } else {
            // Narrow widths get a 3-row layout: location on its own line, then
            // verdict/conf/cwe/source. Keeps all identifiers visible at 80 cols.
            body.push(indent(
                muted(&fit(&location, area.width.saturating_sub(4) as usize)),
                4,
            ));
            let detail = format!("{verdict} · conf {conf} · {cwe} · {source}");
            body.push(indent(
                muted(&fit(&detail, area.width.saturating_sub(4) as usize)),
                4,
            ));
        }
    }

    let body_height = area.height.saturating_sub(lines.len() as u16) as usize;
    if body_height == 0 {
        return lines;
    }
    let row_height = if area.width >= 100 { 2 } else { 3 };
    let visible_rows = (body_height / row_height).max(1);
    let start_row = viewport_start_for_cursor(app.findings.len(), visible_rows, cursor);
    lines.extend(
        body.into_iter()
            .skip(start_row * row_height)
            .take(body_height),
    );
    lines
}

pub(in crate::renderer) fn finding_detail_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
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

pub(in crate::renderer) fn finding_location(finding: &Finding) -> String {
    match finding.end_line {
        Some(end_line) if end_line > finding.start_line => {
            format!("{}:{}-{}", finding.file_path, finding.start_line, end_line)
        }
        _ => format!("{}:{}", finding.file_path, finding.start_line),
    }
}

pub(in crate::renderer) fn finding_verdict_label(finding: &Finding) -> String {
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

pub(in crate::renderer) fn finding_confidence_label(finding: &Finding) -> String {
    finding
        .triage
        .as_ref()
        .map(|triage| format!("{:.0}%", (triage.confidence.clamp(0.0, 1.0) * 100.0)))
        .unwrap_or_else(|| "-".to_string())
}

pub(in crate::renderer) fn finding_cwe_label(finding: &Finding) -> String {
    extract_cwe(&finding.message)
        .or_else(|| extract_cwe(&finding.rule_id))
        .unwrap_or_else(|| "-".to_string())
}

pub(in crate::renderer) fn extract_cwe(value: &str) -> Option<String> {
    let upper = value.to_ascii_uppercase();
    for (index, _) in upper.match_indices("CWE") {
        let mut rest = upper[index + 3..].chars();
        while matches!(rest.clone().next(), Some('-' | '_' | ' ' | ':')) {
            rest.next();
        }
        let digits = rest
            .take_while(|ch| ch.is_ascii_digit())
            .collect::<String>();
        if !digits.is_empty() {
            return Some(format!("CWE-{digits}"));
        }
    }
    None
}

pub(in crate::renderer) fn finding_source_label(finding: &Finding) -> String {
    if finding.rule_id.is_empty() || finding.rule_id.starts_with(&finding.tool) {
        finding.tool.clone()
    } else {
        format!("{}:{}", finding.tool, finding.rule_id)
    }
}

pub(in crate::renderer) fn finding_evidence_preview(finding: &Finding) -> String {
    let lines = finding
        .message
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();

    if let Some(evidence) = lines.iter().find_map(|line| {
        line.strip_prefix("Evidence:")
            .or_else(|| line.strip_prefix("evidence:"))
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }) {
        return evidence.to_string();
    }

    lines
        .iter()
        .copied()
        .find(|line| *line != finding.title)
        .unwrap_or_else(|| lines.first().copied().unwrap_or(&finding.title))
        .to_string()
}
