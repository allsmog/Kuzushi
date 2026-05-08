use super::*;

pub(super) fn append_finding_table(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
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
        append_finding_row(app, area, index, alias, finding, &mut body);
    }

    let body_height = area.height.saturating_sub(lines.len() as u16) as usize;
    if body_height == 0 {
        return;
    }
    let row_height = if area.width >= 100 { 2 } else { 3 };
    let visible_rows = (body_height / row_height).max(1);
    let start_row = viewport_start_for_cursor(app.findings.len(), visible_rows, cursor);
    lines.extend(
        body.into_iter()
            .skip(start_row * row_height)
            .take(body_height),
    );
}

fn append_finding_row(
    app: &ShellApp,
    area: Rect,
    index: usize,
    alias: String,
    finding: Finding,
    body: &mut Vec<Line<'static>>,
) {
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
    let location = finding_location(&finding);
    let wide = area.width >= 100;
    body.push(finding_summary_line(
        &alias,
        &finding,
        &location,
        marker,
        marker_style,
        area,
        wide,
    ));
    append_finding_detail_lines(&finding, &location, area, wide, body);
}

fn finding_summary_line(
    alias: &str,
    finding: &Finding,
    location: &str,
    marker: &str,
    marker_style: Style,
    area: Rect,
    wide: bool,
) -> Line<'static> {
    let alias_w = 8;
    let sev_w = 9;
    let prefix_used = 2 + alias_w + 2 + sev_w;
    let total = (area.width as usize).saturating_sub(prefix_used);
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
    let mut row = vec![
        Span::styled(marker.to_string(), marker_style),
        Span::styled(pad(alias, alias_w), theme::accent()),
        Span::raw("  "),
        Span::styled(
            pad(&finding.severity.as_str().to_uppercase(), sev_w),
            theme::severity(finding.severity),
        ),
        Span::styled(pad(&fit(&finding.title, name_w), name_w), theme::primary()),
    ];
    if wide {
        row.push(Span::raw("  "));
        row.push(Span::styled(fit(location, location_w), theme::muted()));
    }
    Line::from(row)
}

fn append_finding_detail_lines(
    finding: &Finding,
    location: &str,
    area: Rect,
    wide: bool,
    body: &mut Vec<Line<'static>>,
) {
    let verdict = finding_verdict_label(finding);
    let conf = finding_confidence_label(finding);
    let cwe = finding_cwe_label(finding);
    let source = finding_source_label(finding);
    let evidence = finding_evidence_preview(finding);
    if wide {
        let detail = format!("{verdict} · conf {conf} · {cwe} · {source} · {evidence}");
        body.push(indent(
            muted(&fit(&detail, area.width.saturating_sub(4) as usize)),
            4,
        ));
        return;
    }
    body.push(indent(
        muted(&fit(location, area.width.saturating_sub(4) as usize)),
        4,
    ));
    let detail = format!("{verdict} · conf {conf} · {cwe} · {source}");
    body.push(indent(
        muted(&fit(&detail, area.width.saturating_sub(4) as usize)),
        4,
    ));
}
