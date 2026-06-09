use super::*;
use crate::ui_view_models::{FindingListRow, FindingsModel};

pub(super) fn append_finding_table(
    model: &FindingsModel,
    area: Rect,
    lines: &mut Vec<Line<'static>>,
) {
    lines.push(section_header_line(&model.header, area.width));

    let mut body = Vec::new();
    for row in &model.rows {
        append_finding_row(area, row, &mut body);
    }

    let body_height = area.height.saturating_sub(lines.len() as u16) as usize;
    if body_height == 0 {
        return;
    }
    let row_height = if area.width >= 100 { 2 } else { 3 };
    let visible_rows = (body_height / row_height).max(1);
    let start_row = viewport_start_for_cursor(model.total, visible_rows, model.cursor);
    lines.extend(
        body.into_iter()
            .skip(start_row * row_height)
            .take(body_height),
    );
}

fn append_finding_row(area: Rect, row: &FindingListRow, body: &mut Vec<Line<'static>>) {
    let marker = if row.cursor {
        "▌ "
    } else if row.selected {
        "* "
    } else {
        "  "
    };
    let marker_style = if row.cursor {
        theme::accent()
    } else if row.selected {
        theme::warn()
    } else {
        theme::subtle()
    };
    let wide = area.width >= 100;
    body.push(finding_summary_line(row, marker, marker_style, area, wide));
    append_finding_detail_lines(row, area, wide, body);
}

fn finding_summary_line(
    finding: &FindingListRow,
    marker: &str,
    marker_style: Style,
    area: Rect,
    wide: bool,
) -> Line<'static> {
    let widths = finding_summary_widths(finding, area, wide);
    let mut row = finding_summary_spans(finding, marker, marker_style, widths.title);
    if wide {
        row.push(Span::raw("  "));
        row.push(Span::styled(
            fit_path(&finding.location, widths.location),
            theme::muted(),
        ));
    }
    Line::from(row)
}

struct FindingSummaryWidths {
    title: usize,
    location: usize,
}

fn finding_summary_widths(
    finding: &FindingListRow,
    area: Rect,
    wide: bool,
) -> FindingSummaryWidths {
    let total = (area.width as usize).saturating_sub(21);
    let location = wide_location_width(finding, total, wide);
    let title = if wide {
        total.saturating_sub(location + 2).max(12)
    } else {
        total.max(12)
    };
    FindingSummaryWidths { title, location }
}

fn wide_location_width(finding: &FindingListRow, total: usize, wide: bool) -> usize {
    // Keep at least TITLE_MIN columns for the title so a deep path can't crush
    // it; the path itself left-truncates to keep `file.rs:line` visible.
    const TITLE_MIN: usize = 30;
    if wide {
        {
            let cap = total.saturating_sub(TITLE_MIN + 2).max(8);
            finding.location.chars().count().min(cap).max(8)
        }
    } else {
        0
    }
}

fn finding_summary_spans(
    finding: &FindingListRow,
    marker: &str,
    marker_style: Style,
    title_w: usize,
) -> Vec<Span<'static>> {
    vec![
        Span::styled(marker.to_string(), marker_style),
        Span::styled(pad(&finding.alias, 8), theme::accent()),
        Span::raw("  "),
        Span::styled(
            pad(&finding.severity_label, 9),
            theme::severity_tone(finding.severity_tone),
        ),
        Span::styled(
            pad(&fit(&finding.title, title_w), title_w),
            theme::primary(),
        ),
    ]
}

fn append_finding_detail_lines(
    finding: &FindingListRow,
    area: Rect,
    wide: bool,
    body: &mut Vec<Line<'static>>,
) {
    if wide {
        let detail = compose_detail_line(finding, true);
        body.push(indent(
            muted(&fit(&detail, area.width.saturating_sub(4) as usize)),
            4,
        ));
        return;
    }
    body.push(indent(
        muted(&fit(
            &finding.location,
            area.width.saturating_sub(4) as usize,
        )),
        4,
    ));
    let detail = compose_detail_line(finding, false);
    body.push(indent(
        muted(&fit(&detail, area.width.saturating_sub(4) as usize)),
        4,
    ));
}

fn compose_detail_line(finding: &FindingListRow, include_evidence: bool) -> String {
    let mut parts: Vec<String> = vec![finding.verdict.clone()];
    if finding.confidence != "-" {
        parts.push(format!("conf {}", finding.confidence));
    }
    if finding.cwe != "-" {
        parts.push(finding.cwe.clone());
    }
    parts.push(finding.source.clone());
    if include_evidence && !finding.evidence.is_empty() && finding.evidence != finding.title {
        parts.push(finding.evidence.clone());
    }
    parts.join(" · ")
}
