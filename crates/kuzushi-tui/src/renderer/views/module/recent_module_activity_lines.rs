use super::*;
use crate::ui_view_models::{
    recent_module_activity_model, ModuleActivityKind, ModuleActivityModel, ModuleActivityRow,
    ModuleActivityTone,
};

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
    let [first, second, third, fourth] = row.cells;
    match row.kind {
        ModuleActivityKind::Transcript => transcript_line(&first, &second, false),
        ModuleActivityKind::ReconService => Line::from(vec![
            Span::styled(" ▸ ", theme::warn()),
            Span::styled(first, theme::primary()),
            Span::styled(":", theme::subtle()),
            Span::styled(second, theme::accent()),
            Span::raw("  "),
            Span::styled(pad(&third, 14), theme::muted()),
            Span::styled(fourth, theme::primary()),
        ]),
        ModuleActivityKind::ReconHost => Line::from(vec![
            Span::styled(" ▸ ", theme::warn()),
            Span::styled(first, theme::primary()),
            Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
            Span::styled(second, theme::muted()),
        ]),
        ModuleActivityKind::Finding => {
            module_activity_finding_line(row.tone, &first, &second, &third)
        }
    }
}

#[cfg(test)]
pub(crate) fn transcript_finding_line(
    severity: Severity,
    rule_id: &str,
    location: &str,
) -> Line<'static> {
    module_activity_finding_line(
        ModuleActivityTone::from_severity(severity),
        &severity.as_str().to_uppercase(),
        rule_id,
        location,
    )
}

fn module_activity_finding_line(
    tone: ModuleActivityTone,
    severity: &str,
    rule_id: &str,
    location: &str,
) -> Line<'static> {
    Line::from(vec![
        Span::styled(" ▸ ", theme::warn()),
        Span::styled(format!("{severity:9}"), module_activity_tone_style(tone)),
        Span::raw(" "),
        Span::styled(rule_id.to_string(), theme::accent()),
        Span::raw("  "),
        Span::styled(location.to_string(), theme::muted()),
    ])
}

fn module_activity_tone_style(tone: ModuleActivityTone) -> Style {
    match tone {
        ModuleActivityTone::Critical => theme::severity(Severity::Critical),
        ModuleActivityTone::High => theme::severity(Severity::High),
        ModuleActivityTone::Medium => theme::severity(Severity::Medium),
        ModuleActivityTone::Low => theme::severity(Severity::Low),
        ModuleActivityTone::Info => theme::severity(Severity::Info),
        ModuleActivityTone::Unknown => theme::severity(Severity::Unknown),
        ModuleActivityTone::Default => theme::muted(),
    }
}
