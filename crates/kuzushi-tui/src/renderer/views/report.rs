use super::*;

pub(crate) fn report_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let route = app.router.report();
    if route.editing_path() {
        return report_path_editor_lines(route, area);
    }
    let mut lines = vec![report_selection_line(route, area.width)];
    lines.extend(viewport_lines(
        report_document_lines(app, area),
        area.height.saturating_sub(1),
        app.router.default_scroll().offset() as usize,
    ));
    lines
}

fn report_selection_line(route: &crate::app::ReportRouteState, width: u16) -> Line<'static> {
    let prefix = format!(
        "{} · {} · ",
        route.format().as_str(),
        route.completeness().as_str()
    );
    let path = fit_path(
        route.path_draft(),
        (width as usize).saturating_sub(prefix.chars().count()),
    );
    Line::styled(format!("{prefix}{path}"), theme::accent())
}

fn report_document_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let route = app.router.report();
    let mut lines = report_header_lines(app, area);
    append_report_status(&mut lines, route, area.width);
    for line in crate::ui_view_models::report_investigation_lines(app) {
        append_wrapped(&mut lines, &line, area.width);
    }
    if route.provenance_details() {
        if let Some(receipt) = route.receipt() {
            append_report_receipt(&mut lines, receipt, area.width);
        }
    }
    lines.push(blank());
    append_report_formats(&mut lines, route, area.width);
    append_report_destination(&mut lines, route, area.width);
    lines.push(blank());
    append_wrapped(
        &mut lines,
        &crate::ui_view_models::report_cost_coverage(app),
        area.width,
    );
    lines.push(blank());
    append_wrapped(
        &mut lines,
        &report_actions(route.receipt()).join(" · "),
        area.width,
    );
    lines
}

pub(crate) fn report_offset_after_page(app: &ShellApp, direction: isize) -> usize {
    let viewport = app.viewport();
    let area =
        crate::renderer::primary_body_area(app, Rect::new(0, 0, viewport.columns, viewport.rows));
    let maximum = report_document_lines(app, area)
        .len()
        .saturating_sub(area.height.saturating_sub(1) as usize);
    let start = (app.router.default_scroll().offset() as usize).min(maximum);
    let step = area.height.saturating_sub(2).max(1) as isize;
    start.saturating_add_signed(direction * step).min(maximum)
}

fn report_header_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("REPORT", area.width));
    append_wrapped(
        &mut lines,
        &crate::ui_view_models::report_review_summary(app),
        area.width,
    );
    lines.push(blank());
    lines
}

fn append_report_formats(
    lines: &mut Vec<Line<'static>>,
    route: &crate::app::ReportRouteState,
    width: u16,
) {
    append_wrapped(
        lines,
        &format!(
            "format  {} ({}/{}) · {}",
            route.format().as_str(),
            route.format_index() + 1,
            crate::app::ReportRouteState::FORMATS.len(),
            format_description(route.format())
        ),
        width,
    );
    append_wrapped(
        lines,
        "sarif · markdown-bundle · jsonl · json · csv · vuln-findings",
        width,
    );
}

fn append_report_destination(
    lines: &mut Vec<Line<'static>>,
    route: &crate::app::ReportRouteState,
    width: u16,
) {
    lines.push(blank());
    lines.push(detail("completeness", route.completeness().as_str()));
    append_wrapped(
        lines,
        &format!("destination  {}", route.path_draft()),
        width,
    );
}

fn report_path_editor_lines(
    route: &crate::app::ReportRouteState,
    area: Rect,
) -> Vec<Line<'static>> {
    let mut lines = vec![divider("EXPORT DESTINATION", area.width)];
    append_wrapped(
        &mut lines,
        "Enter / Ctrl+S save path · Esc cancel",
        area.width,
    );
    lines.push(blank());
    if let Some(field) = route.path_edit() {
        lines.extend(crate::renderer::shared::field_editor_lines(
            field,
            area.width as usize,
            area.height.saturating_sub(7).max(1) as usize,
        ));
    }
    if let Some(error) = route.path_error() {
        append_wrapped(&mut lines, error, area.width);
    }
    lines
}

fn append_wrapped(lines: &mut Vec<Line<'static>>, text: &str, width: u16) {
    lines.extend(
        wrap_text(text, width.max(1) as usize)
            .into_iter()
            .map(Line::from),
    );
}

fn append_report_status(
    lines: &mut Vec<Line<'static>>,
    route: &crate::app::ReportRouteState,
    width: u16,
) {
    append_wrapped(lines, &route.choices_status(), width);
    if let Some(receipt) = route.receipt() {
        append_report_status_summary(lines, receipt, width);
    }
    if let Some(error) = route.reveal_error() {
        append_wrapped(lines, &format!("reveal  {error}"), width);
    }
}

fn append_report_status_summary(
    lines: &mut Vec<Line<'static>>,
    receipt: &crate::app::ReportReceipt,
    width: u16,
) {
    let title = if receipt.error.is_some() {
        "EXPORT FAILED"
    } else {
        "EXPORTED"
    };
    lines.push(divider(title, width));
    for line in compact_receipt_lines(receipt) {
        append_wrapped(lines, &line, width);
    }
    if let Some(error) = &receipt.error {
        append_wrapped(lines, error, width);
    }
}

/// What happened and when. The long destination path stays in `p` details so
/// study facts keep their place above it.
fn compact_receipt_lines(receipt: &crate::app::ReportReceipt) -> Vec<String> {
    let count = receipt.count.map_or_else(
        || "count unavailable".to_string(),
        |count| format!("{count} finding(s)"),
    );
    vec![
        format!("{} · {count} · p receipt details", receipt.format.as_str()),
        format!(
            "timestamp {}",
            crate::ui_view_models::recorded_timestamp_label(&receipt.timestamp)
        ),
    ]
}

fn report_actions(receipt: Option<&crate::app::ReportReceipt>) -> [&'static str; 9] {
    let export = match receipt {
        Some(receipt) if receipt.error.is_some() => "Enter retry",
        Some(_) => "Enter export again",
        None => "Enter export",
    };
    [
        "j/k format",
        "c completeness",
        "s study/history",
        "p provenance",
        "e edit path",
        "S save choices",
        export,
        if receipt.is_some() {
            "o reveal destination"
        } else {
            "o reveal after export"
        },
        "Esc return",
    ]
}

#[cfg(test)]
mod selection_tests {
    use super::*;

    #[test]
    fn report_format_and_destination_remain_visible_while_paging_at_every_width() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_shell_view(crate::app::ShellView::Report);
        app.router.report_mut().move_format(3);
        for width in [40, 60, 80, 96, 120, 160] {
            for offset in [0, 10, u16::MAX] {
                app.router.default_scroll_mut().set(offset);
                let lines = report_lines(&app, Rect::new(0, 0, width, 8));
                let text = lines[0].to_string();
                assert!(text.starts_with("json · all ·"), "{width}: {text}");
                assert!(text.contains("findings.json"), "{width}: {text}");
                assert!(text.chars().count() <= width as usize);
            }
        }
        app.router.report_mut().move_format(-1);
        assert!(report_lines(&app, Rect::new(0, 0, 40, 8))[0]
            .to_string()
            .contains("jsonl"));
    }
}

fn format_description(format: kuzushi_core::WorkspaceExportFormat) -> &'static str {
    match format {
        kuzushi_core::WorkspaceExportFormat::Sarif => "tooling interchange",
        kuzushi_core::WorkspaceExportFormat::MarkdownBundle => "human review bundle",
        kuzushi_core::WorkspaceExportFormat::Jsonl => "streaming records",
        kuzushi_core::WorkspaceExportFormat::Json => "structured document",
        kuzushi_core::WorkspaceExportFormat::Csv => "flat spreadsheet",
        kuzushi_core::WorkspaceExportFormat::VulnFindings => "external triage schema",
    }
}

fn append_report_receipt(
    lines: &mut Vec<Line<'static>>,
    receipt: &crate::app::ReportReceipt,
    width: u16,
) {
    lines.push(blank());
    lines.push(divider("EXPORT RECEIPT", width));
    lines.push(detail("format", receipt.format.as_str()));
    lines.push(detail("completeness", receipt.completeness.as_str()));
    lines.push(detail(
        "timestamp",
        &crate::ui_view_models::recorded_timestamp_label(&receipt.timestamp),
    ));
    if let Some(count) = receipt.count {
        lines.push(detail("findings", &count.to_string()));
    }
    append_report_paths(lines, receipt, width);
    if let Some(error) = receipt.error.as_ref() {
        append_wrapped(lines, &format!("error  {error}"), width);
    }
}

fn append_report_paths(
    lines: &mut Vec<Line<'static>>,
    receipt: &crate::app::ReportReceipt,
    width: u16,
) {
    for (label, path) in [
        ("path", &receipt.absolute_path),
        ("investigation receipt", &receipt.investigation_receipt_path),
    ] {
        if let Some(path) = path {
            append_wrapped(lines, &format!("{label}  {}", path.display()), width);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn report_header_never_presents_campaign_spend_as_a_workspace_total() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.router.campaign_mut().trend = Some(
            kuzushi_core::capabilities::campaign::trend::trend_metrics(&[], 8.0),
        );
        let text = report_document_lines(&app, Rect::new(0, 0, 120, 30))
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            text.contains("Workspace spend: total unavailable"),
            "{text}"
        );
        assert!(!text.contains("$8.00 spent"), "{text}");
    }

    #[test]
    fn report_status_does_not_push_scope_below_export_paths() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(crate::ShellView::Report);
        app.router.report_mut().toggle_scope();
        app.router
            .report_mut()
            .set_receipt(crate::app::ReportReceipt {
                format: kuzushi_core::WorkspaceExportFormat::Json,
                completeness: kuzushi_core::WorkspaceExportCompleteness::All,
                count: Some(1),
                absolute_path: Some("/long/export/destination.json".into()),
                investigation_receipt_path: None,
                error: None,
                timestamp: "test".into(),
            });
        let text = report_document_lines(&app, Rect::new(0, 0, 80, 24))
            .iter()
            .map(Line::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("EXPORTED"));
        assert!(text.contains("json · 1 finding(s) · p receipt details"));
        assert!(text.contains("timestamp"));
        assert!(!text.contains("/long/export"));
        app.router.report_mut().toggle_provenance();
        let detail = report_document_lines(&app, Rect::new(0, 0, 80, 24))
            .iter()
            .map(Line::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            detail.find("Scope: workspace history").unwrap() < detail.find("/long/export").unwrap()
        );
    }

    #[test]
    fn report_destination_editor_keeps_long_unicode_cursor_visible() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.router.report_mut().set_editing_path(true);
        app.router
            .report_mut()
            .insert_path_text(&"a directory, 界/".repeat(20));
        for width in [40, 80, 120] {
            let lines = report_lines(&app, Rect::new(0, 0, width, 12));
            assert!(lines.iter().all(|line| line.width() <= width as usize));
            assert!(lines.iter().flat_map(|line| &line.spans).any(|span| span
                .style
                .add_modifier
                .contains(ratatui::style::Modifier::REVERSED)));
            assert!(!lines
                .iter()
                .any(|line| line.to_string().contains("j/k format")));
        }
    }

    #[test]
    fn report_receipt_wraps_the_complete_destination_and_error() {
        let receipt = crate::app::ReportReceipt {
            format: kuzushi_core::WorkspaceExportFormat::Sarif,
            completeness: kuzushi_core::WorkspaceExportCompleteness::All,
            count: None,
            absolute_path: Some(format!("/{}last.sarif", "long-directory/".repeat(12)).into()),
            investigation_receipt_path: None,
            error: Some(format!(
                "{}recovery detail",
                "cannot write destination ".repeat(8)
            )),
            timestamp: "test".into(),
        };
        let mut lines = Vec::new();
        append_report_receipt(&mut lines, &receipt, 40);
        assert!(lines.iter().all(|line| line.width() <= 40));
        let text = lines
            .iter()
            .map(Line::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(text.contains("last.sarif"));
        assert!(text.contains("recovery detail"));
    }

    #[test]
    fn report_document_pages_to_its_tail_without_losing_the_editor() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(crate::ShellView::Report);
        app.set_input_mode(crate::InputMode::Navigate);
        app.set_viewport(crate::TerminalViewport::new(40, 12));
        app.router
            .report_mut()
            .set_receipt(crate::app::ReportReceipt {
                format: kuzushi_core::WorkspaceExportFormat::Sarif,
                completeness: kuzushi_core::WorkspaceExportCompleteness::All,
                count: None,
                absolute_path: None,
                investigation_receipt_path: None,
                error: Some(format!(
                    "{}LAST RECOVERY DETAIL",
                    "Export failed because the path is unavailable. ".repeat(20)
                )),
                timestamp: "test".into(),
            });
        let before = rendered_report(&app, 40, 12);
        for _ in 0..40 {
            app.reduce_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        }
        let tail = rendered_report(&app, 40, 12);
        assert_ne!(before, tail, "Report must be scrollable");
        app.reduce_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
        assert_ne!(
            tail,
            rendered_report(&app, 40, 12),
            "paging back must not repay overscroll"
        );
        app.router.report_mut().set_editing_path(true);
        let editing = rendered_report(&app, 40, 12);
        assert!(editing.contains("EXPORT DESTINATION"), "{editing}");
        assert!(
            editing.contains(".kuzushi/reports/report.sarif"),
            "{editing}"
        );
    }

    fn rendered_report(app: &ShellApp, width: u16, height: u16) -> String {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, app))
            .unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }
}
