use super::*;

pub(crate) fn report_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let route = app.router.report();
    let mut lines = report_header_lines(app, area);
    append_report_formats(&mut lines, route);
    append_report_destination(&mut lines, route);
    append_report_status(&mut lines, route, area.width);
    lines.push(blank());
    lines.push(command_list_line(
        &report_actions(
            route.receipt().is_some(),
            route
                .receipt()
                .is_some_and(|receipt| receipt.error.is_some()),
        ),
        area.width as usize,
    ));
    lines
}

fn report_header_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("REPORT · EXPORT EXIT", area.width));
    lines.push(Line::from(Span::styled(
        "Choose one durable export. Success and failure stay here as receipts.",
        theme::muted(),
    )));
    if let Some(trend) = &app.router.campaign().trend {
        lines.push(Line::from(Span::styled(
            trend.strip_label(),
            theme::subtle(),
        )));
        if let Some(history) =
            kuzushi_core::capabilities::campaign::trend_history::history_strip_label(
                &app.router.campaign().trend_history,
            )
        {
            lines.push(Line::from(Span::styled(history, theme::subtle())));
        }
    }
    lines.push(blank());
    lines
}

fn append_report_formats(lines: &mut Vec<Line<'static>>, route: &crate::app::ReportRouteState) {
    for (index, format) in crate::app::ReportRouteState::FORMATS.iter().enumerate() {
        let marker = if index == route.format_index() {
            "▸"
        } else {
            " "
        };
        let style = if index == route.format_index() {
            theme::accent()
        } else {
            theme::primary()
        };
        lines.push(Line::from(Span::styled(
            format!(
                "{marker} {:<16} {}",
                format.as_str(),
                format_description(*format)
            ),
            style,
        )));
    }
}

fn append_report_destination(lines: &mut Vec<Line<'static>>, route: &crate::app::ReportRouteState) {
    lines.push(blank());
    lines.push(detail("completeness", route.completeness().as_str()));
    let cursor = if route.editing_path() { "▏" } else { "" };
    lines.push(detail(
        "destination",
        &format!("{}{}", route.path_draft(), cursor),
    ));
}

fn append_report_status(
    lines: &mut Vec<Line<'static>>,
    route: &crate::app::ReportRouteState,
    width: u16,
) {
    if let Some(receipt) = route.receipt() {
        append_report_receipt(lines, receipt, width);
    }
    if let Some(error) = route.reveal_error() {
        lines.push(Line::from(vec![
            Span::styled("reveal  ", theme::danger()),
            Span::styled(error.to_string(), theme::primary()),
        ]));
    }
}

fn report_actions(has_receipt: bool, failed: bool) -> [&'static str; 6] {
    if has_receipt && !failed {
        return [
            "j/k format",
            "c completeness",
            "e edit path",
            "Enter export again",
            "o Reveal Destination",
            "Esc Return",
        ];
    }
    if has_receipt {
        [
            "j/k format",
            "c completeness",
            "e edit path",
            "Enter Retry",
            "o reveal after successful export",
            "Esc Return",
        ]
    } else {
        [
            "j/k format",
            "c completeness",
            "e edit path",
            "Enter export",
            "o reveal after export",
            "Esc Return",
        ]
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
    lines.push(divider("LAST EXPORT RECEIPT", width));
    lines.push(detail("format", receipt.format.as_str()));
    lines.push(detail("completeness", receipt.completeness.as_str()));
    lines.push(detail("timestamp", &receipt.timestamp));
    if let Some(count) = receipt.count {
        lines.push(detail("findings", &count.to_string()));
    }
    if let Some(path) = receipt.absolute_path.as_ref() {
        lines.push(detail("path", &path.display().to_string()));
    }
    if let Some(error) = receipt.error.as_ref() {
        lines.push(Line::from(vec![
            Span::styled("error  ", theme::danger()),
            Span::styled(error.clone(), theme::primary()),
        ]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn report_header_carries_the_workspace_trend_strip_when_folded() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.router.campaign_mut().trend = Some(
            kuzushi_core::capabilities::campaign::trend::trend_metrics(&[], 8.0),
        );
        let text = report_lines(&app, Rect::new(0, 0, 120, 30))
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("TREND  FP rate — (no decisions)"), "{text}");
        assert!(text.contains("$8.00 spent"), "{text}");
    }
}

#[cfg(test)]
mod export_action_tests {
    use super::report_actions;

    #[test]
    fn successful_export_is_not_presented_as_a_failure_to_retry() {
        let actions = report_actions(true, false);
        assert!(actions.contains(&"Enter export again"));
        assert!(actions.contains(&"o Reveal Destination"));
        assert!(!actions.contains(&"Enter Retry"));
    }

    #[test]
    fn failed_export_offers_retry_without_claiming_a_revealable_file() {
        let actions = report_actions(true, true);
        assert!(actions.contains(&"Enter Retry"));
        assert!(!actions.contains(&"o Reveal Destination"));
    }

    #[test]
    fn new_export_keeps_the_original_export_action() {
        assert!(report_actions(false, false).contains(&"Enter export"));
    }
}
