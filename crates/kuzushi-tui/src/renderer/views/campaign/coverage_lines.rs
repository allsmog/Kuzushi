use super::*;
use kuzushi_core::capabilities::campaign::coverage::{
    CoverageCellState, CoverageReport, CoverageRow,
};

const SHARD_COLUMN_WIDTH: usize = 28;
const FINDINGS_COLUMN_WIDTH: usize = 12;

pub(crate) fn coverage_page_rows(app: &ShellApp) -> Option<usize> {
    if app.shell_view() != ShellView::Coverage {
        return None;
    }
    let viewport = app.viewport();
    let area = crate::renderer::workbench_primary_area(
        app,
        Rect::new(0, 0, viewport.columns, viewport.rows),
    );
    Some(usize::from(area.height).saturating_sub(1).max(1))
}

/// The Coverage deck: shards down, threat sources across, one glyph per
/// cell, per-shard finding counts on the tail. Read-only over the shared
/// coverage fold (`campaign:coverage` is the headless twin).
pub(crate) fn coverage_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("HISTORICAL SHARD PROGRESS", area.width));
    let deck = app.router.coverage();
    if let Some(notice) = &deck.notice {
        lines.push(Line::styled(format!("  {notice}"), theme::warn()));
        return lines;
    }
    let Some(report) = &deck.report else {
        lines.push(Line::styled(
            "  no coverage report loaded — run `coverage` with an active target",
            theme::subtle(),
        ));
        return lines;
    };
    append_matrix(&mut lines, report, area);
    lines
}

fn append_matrix(lines: &mut Vec<Line<'static>>, report: &CoverageReport, area: Rect) {
    let visible = visible_columns(report, area);
    append_progress_qualifications(lines, report, area.width as usize);
    append_progress_table(lines, report, visible, area.width as usize);
}

fn append_progress_qualifications(
    lines: &mut Vec<Line<'static>>,
    report: &CoverageReport,
    width: usize,
) {
    push_deck_text(
        lines,
        &format!(
            "  {} campaign(s) folded · {} shard(s) × {} threat source(s)",
            report.campaign_count,
            report.rows.len(),
            report.columns.len()
        ),
        width,
        theme::subtle(),
    );
    if report.unreadable_campaigns > 0 {
        // Degraded fold: skipped campaigns mean cells can under-report.
        push_deck_text(lines, &format!(
                "  Warning: {} campaign dir(s) unreadable; their progress is absent from this matrix",
                report.unreadable_campaigns
            ), width, theme::warn());
    }
    push_deck_text(
        lines,
        "Job completion is not repository coverage or current-source applicability.",
        width,
        theme::warn(),
    );
    push_deck_text(lines, &format!("{} preparation, unclassified or non-shard job(s) excluded. Accepted scope studies use Report.", report.excluded_jobs), width, theme::subtle());
}

fn append_progress_table(
    lines: &mut Vec<Line<'static>>,
    report: &CoverageReport,
    visible: usize,
    width: usize,
) {
    lines.push(blank());
    lines.push(matrix_header(visible));
    for row in &report.rows {
        lines.push(matrix_row(row, visible));
    }
    if visible < report.columns.len() {
        lines.push(Line::styled(
            format!(
                "  … {} more column(s) — widen the terminal to see them",
                report.columns.len() - visible
            ),
            theme::warn(),
        ));
    }
    append_column_key(lines, report, visible);
    lines.push(blank());
    push_deck_text(lines, "✓ completed · ◔ partial · ◐ running · ✗ failed/parked · ○ planned · never. Finding counts include saved findings and confirmed verdicts under the shard paths.", width, theme::subtle());
    if report.campaign_count == 0 {
        lines.push(blank());
        push_deck_text(lines, "No legacy campaigns. Plan accepted scopes with campaign:study; this matrix is a compatibility reader.", width, theme::subtle());
    }
}

fn visible_columns(report: &CoverageReport, area: Rect) -> usize {
    let cell_budget =
        (area.width as usize).saturating_sub(SHARD_COLUMN_WIDTH + FINDINGS_COLUMN_WIDTH + 4);
    (cell_budget / 2).max(1).min(report.columns.len())
}

fn matrix_header(visible: usize) -> Line<'static> {
    let mut header = format!("  {:<width$}", "shard", width = SHARD_COLUMN_WIDTH);
    for index in 1..=visible {
        header.push_str(&format!("{:>2}", column_tag(index)));
    }
    header.push_str("  findings");
    Line::styled(header, theme::accent())
}

fn matrix_row(row: &CoverageRow, visible: usize) -> Line<'static> {
    let mut spans = vec![Span::styled(
        format!(
            "  {:<width$}",
            fit(&row.shard, SHARD_COLUMN_WIDTH),
            width = SHARD_COLUMN_WIDTH
        ),
        theme::primary(),
    )];
    for cell in row.cells.iter().take(visible) {
        spans.push(Span::styled(
            format!(" {}", cell_glyph(*cell)),
            cell_style(*cell),
        ));
    }
    if row.cells.is_empty() {
        spans.push(Span::styled(" ·", theme::subtle()));
    }
    spans.push(Span::styled(
        format!("  {} ({}✔)", row.finding_count, row.confirmed_count),
        if row.confirmed_count > 0 {
            theme::warn()
        } else {
            theme::subtle()
        },
    ));
    Line::from(spans)
}

/// Column tags 1-9 then a-z keep the header two characters wide regardless
/// of how many threat-model documents the workspace carries.
fn column_tag(index: usize) -> String {
    if index <= 9 {
        index.to_string()
    } else {
        char::from_u32('a' as u32 + (index - 10) as u32 % 26)
            .unwrap_or('?')
            .to_string()
    }
}

fn append_column_key(lines: &mut Vec<Line<'static>>, report: &CoverageReport, visible: usize) {
    if report.columns.is_empty() {
        return;
    }
    lines.push(blank());
    lines.push(Line::styled("  columns:", theme::accent()));
    for (index, column) in report.columns.iter().take(visible).enumerate() {
        lines.push(Line::styled(
            format!("   {:>2}  {}", column_tag(index + 1), column),
            theme::subtle(),
        ));
    }
}

fn cell_glyph(state: CoverageCellState) -> &'static str {
    match state {
        CoverageCellState::Never => "·",
        CoverageCellState::Partial => "◔",
        CoverageCellState::Planned => "○",
        CoverageCellState::Failed => "✗",
        CoverageCellState::Running => "◐",
        CoverageCellState::Completed => "✓",
    }
}

fn cell_style(state: CoverageCellState) -> Style {
    match state {
        CoverageCellState::Never => theme::subtle(),
        CoverageCellState::Partial => theme::warn(),
        CoverageCellState::Planned => theme::primary(),
        CoverageCellState::Failed => theme::danger(),
        CoverageCellState::Running => theme::accent(),
        CoverageCellState::Completed => theme::success(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    fn report_fixture() -> CoverageReport {
        CoverageReport {
            columns: vec!["archive".to_string(), "blobstore".to_string()],
            campaign_count: 2,
            unreadable_campaigns: 0,
            excluded_jobs: 0,
            rows: vec![
                CoverageRow {
                    shard: "parsers".to_string(),
                    paths: vec!["src/codec".to_string()],
                    cells: vec![CoverageCellState::Completed, CoverageCellState::Never],
                    finding_count: 4,
                    confirmed_count: 1,
                },
                CoverageRow {
                    shard: "api".to_string(),
                    paths: vec!["src/api".to_string()],
                    cells: vec![CoverageCellState::Failed, CoverageCellState::Planned],
                    finding_count: 0,
                    confirmed_count: 0,
                },
            ],
        }
    }

    fn rendered(app: &ShellApp) -> String {
        coverage_lines(app, Rect::new(0, 0, 100, 30))
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn degraded_fold_discloses_unreadable_campaigns() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut report = report_fixture();
        report.unreadable_campaigns = 2;
        app.router.coverage_mut().report = Some(report);

        let text = rendered(&app);

        assert!(
            text.contains("2 campaign dir(s) unreadable"),
            "degraded fold must be disclosed: {text}"
        );
    }

    #[test]
    fn empty_progress_has_no_phantom_column_and_discloses_excluded_jobs() {
        let mut report = report_fixture();
        report.columns.clear();
        report.excluded_jobs = 6;
        for row in &mut report.rows {
            row.cells.clear();
        }
        assert_eq!(visible_columns(&report, Rect::new(0, 0, 40, 12)), 0);
        let mut app = ShellApp::new(V2Config::default(), None);
        app.router.coverage_mut().report = Some(report);
        let text = rendered(&app);
        assert!(text.contains("HISTORICAL SHARD PROGRESS"));
        assert!(text.contains("6 preparation, unclassified or non-shard job(s) excluded"));
        assert!(text.contains("not repository coverage"));
    }

    #[test]
    fn progress_qualifications_wrap_without_losing_the_supported_route() {
        let mut report = report_fixture();
        report.excluded_jobs = 6;
        for width in [40, 60, 80, 96, 120, 160] {
            let mut lines = Vec::new();
            append_progress_qualifications(&mut lines, &report, width);
            let text = lines
                .iter()
                .map(|line| {
                    line.spans
                        .iter()
                        .map(|span| span.content.as_ref())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join(" ");
            let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(normalized.contains("Accepted scope studies use Report."));
            assert!(lines.iter().all(|line| line.width() <= width));
        }
    }

    #[test]
    fn matrix_renders_cells_counts_and_column_key() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.router.coverage_mut().report = Some(report_fixture());

        let text = rendered(&app);

        assert!(text.contains("parsers"));
        assert!(text.contains("✓ ·"));
        assert!(text.contains("4 (1✔)"));
        assert!(text.contains("✗ ○"));
        assert!(text.contains("1  archive"));
        assert!(text.contains("2  blobstore"));
        assert!(text.contains("2 campaign(s) folded"));
    }

    #[test]
    fn notice_renders_instead_of_an_empty_matrix() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.router.coverage_mut().notice = Some("select a target to fold coverage".to_string());

        assert!(rendered(&app).contains("select a target to fold coverage"));
    }
}
