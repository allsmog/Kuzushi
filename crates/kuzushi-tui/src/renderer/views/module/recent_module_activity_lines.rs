use super::*;
use crate::ui_view_models::{
    recent_module_activity_model, ModuleActivityKind, ModuleActivityModel, ModuleActivityRow,
    ModuleActivityTone, SeverityTone,
};

pub(crate) fn recent_module_activity_lines(
    app: &ShellApp,
    module_id: &str,
    take: usize,
) -> Vec<Line<'static>> {
    module_activity_lines(recent_module_activity_model(app, module_id, take))
}

pub(crate) fn recon_snapshot_activity_lines(
    snapshot: &crate::ReconSnapshot,
    take: usize,
) -> Vec<Line<'static>> {
    module_activity_lines(crate::ui_view_models::recon_snapshot_activity_model(
        snapshot, take,
    ))
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
        ModuleActivityKind::ReconNote => Line::from(vec![
            Span::styled(" ▸ note ", theme::warn()),
            Span::styled(first, theme::accent()),
            Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
            Span::styled(second, theme::muted()),
            Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
            Span::styled(third, theme::primary()),
        ]),
        ModuleActivityKind::Finding => {
            module_activity_finding_line(row.tone, &first, &second, &third)
        }
    }
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
        ModuleActivityTone::Critical => theme::severity_tone(SeverityTone::Critical),
        ModuleActivityTone::High => theme::severity_tone(SeverityTone::High),
        ModuleActivityTone::Medium => theme::severity_tone(SeverityTone::Medium),
        ModuleActivityTone::Low => theme::severity_tone(SeverityTone::Low),
        ModuleActivityTone::Info => theme::severity_tone(SeverityTone::Info),
        ModuleActivityTone::Unknown => theme::severity_tone(SeverityTone::Unknown),
        ModuleActivityTone::Default => theme::muted(),
    }
}

#[cfg(test)]
pub(crate) fn transcript_finding_line(
    tone: SeverityTone,
    severity: &str,
    rule_id: &str,
    location: &str,
) -> Line<'static> {
    let tone = match tone {
        SeverityTone::Critical => ModuleActivityTone::Critical,
        SeverityTone::High => ModuleActivityTone::High,
        SeverityTone::Medium => ModuleActivityTone::Medium,
        SeverityTone::Low => ModuleActivityTone::Low,
        SeverityTone::Info => ModuleActivityTone::Info,
        SeverityTone::Unknown => ModuleActivityTone::Unknown,
    };
    module_activity_finding_line(tone, severity, rule_id, location)
}
