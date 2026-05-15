use super::*;
use crate::ui_view_models::{recent_module_activity_model, ModuleActivityModel, ModuleActivityRow};

pub(crate) fn recent_module_activity_lines(
    app: &ShellApp,
    module_id: &str,
    take: usize,
) -> Vec<Line<'static>> {
    module_activity_lines(recent_module_activity_model(app, module_id, take))
}

fn module_activity_lines(model: ModuleActivityModel) -> Vec<Line<'static>> {
    model.rows.into_iter().map(module_activity_line).collect()
}

fn module_activity_line(row: ModuleActivityRow) -> Line<'static> {
    match row {
        ModuleActivityRow::Transcript { prefix, body } => transcript_line(&prefix, &body, false),
        ModuleActivityRow::ReconService {
            host,
            port,
            service,
            banner,
        } => Line::from(vec![
            Span::styled(" ▸ ", theme::warn()),
            Span::styled(host, theme::primary()),
            Span::styled(":", theme::subtle()),
            Span::styled(format!("{port}"), theme::accent()),
            Span::raw("  "),
            Span::styled(pad(&service, 14), theme::muted()),
            Span::styled(banner, theme::primary()),
        ]),
        ModuleActivityRow::ReconHost { label, state } => Line::from(vec![
            Span::styled(" ▸ ", theme::warn()),
            Span::styled(label, theme::primary()),
            Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
            Span::styled(state, theme::muted()),
        ]),
        ModuleActivityRow::Finding {
            severity,
            rule_id,
            location,
        } => transcript_finding_line(severity, &rule_id, &location),
    }
}

pub(crate) fn transcript_finding_line(
    severity: Severity,
    rule_id: &str,
    location: &str,
) -> Line<'static> {
    Line::from(vec![
        Span::styled(" ▸ ", theme::warn()),
        Span::styled(
            format!("{:9}", severity.as_str().to_uppercase()),
            theme::severity(severity),
        ),
        Span::raw(" "),
        Span::styled(rule_id.to_string(), theme::accent()),
        Span::raw("  "),
        Span::styled(location.to_string(), theme::muted()),
    ])
}
