use super::*;
use crate::ui_view_models::{EngagementHeaderModel, JourneyPhaseStatus, WorkbenchHint};
use ratatui::style::Modifier;
use std::time::{SystemTime, UNIX_EPOCH};

pub(in crate::renderer::views) fn phase_header_lines(
    header: &EngagementHeaderModel,
    hints: &[WorkbenchHint],
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![identity_line(header, width)];
    if let Some(rail) = phase_rail_line(&header.phase_rail, width) {
        lines.push(rail);
    }
    lines.extend(next_lines(header, width));
    if width >= 80 && !hints.is_empty() {
        lines.push(command_hint_line(hints, width));
    }
    lines
}

fn identity_line(header: &EngagementHeaderModel, width: usize) -> Line<'static> {
    let mut spans = Vec::new();
    let mut used = 0;
    for (text, style) in identity_atoms(header) {
        push_atom(&mut spans, &mut used, width, text, style);
    }
    Line::from(spans)
}

fn identity_atoms(header: &EngagementHeaderModel) -> Vec<(String, ratatui::style::Style)> {
    let mut atoms = vec![
        ("KUZUSHI".to_string(), theme::heading()),
        (format!("target {}", header.target), theme::label()),
        (format!("view {}", header.phase.word()), theme::label()),
        live_atom(header.live),
    ];
    if header.cost_usd > 0.0 {
        atoms.push((format!("cost ${:.2}", header.cost_usd), theme::primary()));
    }
    atoms.extend([
        (header.context.clone(), context_style(&header.context)),
        (format!("model {}", header.model), theme::muted()),
        (module_atom(&header.module), module_style(&header.module)),
    ]);
    atoms
}

fn module_atom(module: &str) -> String {
    if module == "all modules" {
        return "module all".to_string();
    }
    let module_id = module.split_once(':').map(|(id, _)| id).unwrap_or(module);
    format!("module {module_id}")
}

fn module_style(module: &str) -> ratatui::style::Style {
    if module == "all modules" {
        theme::muted()
    } else {
        theme::accent()
    }
}

fn context_style(context: &str) -> ratatui::style::Style {
    let normalized = context.to_ascii_lowercase();
    if normalized.contains("not built") || normalized.contains("missing") {
        theme::muted()
    } else if normalized.contains("stale") || normalized.contains("partial") {
        theme::warn()
    } else {
        theme::success()
    }
}

fn live_atom(live: bool) -> (String, ratatui::style::Style) {
    if !live {
        return ("○ idle".to_string(), theme::subtle());
    }
    let mut style = theme::success();
    if live_pulse_on() {
        style = style.add_modifier(Modifier::BOLD);
    }
    ("● LIVE".to_string(), style)
}

fn live_pulse_on() -> bool {
    if !theme::cinematic_motion_enabled(theme::active_theme()) {
        return false;
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| (duration.as_millis() / 500) % 2 == 0)
        .unwrap_or(false)
}

fn push_atom(
    spans: &mut Vec<Span<'static>>,
    used: &mut usize,
    width: usize,
    text: String,
    style: ratatui::style::Style,
) {
    let separator_width = usize::from(*used > 0) * 3;
    let atom_width = display_width(&text);
    if used.saturating_add(separator_width + atom_width) > width {
        return;
    }
    if *used > 0 {
        spans.push(Span::styled(" · ", theme::subtle()));
    }
    spans.push(Span::styled(text, style));
    *used += separator_width + atom_width;
}

fn phase_rail_line(statuses: &[JourneyPhaseStatus], width: usize) -> Option<Line<'static>> {
    if statuses.is_empty() || width < 60 {
        return None;
    }
    let mut spans = vec![Span::raw(" ")];
    for (index, status) in statuses.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled(" · ", theme::subtle()));
        }
        let style = journey_phase_tone_style(status.tone);
        spans.push(Span::styled(status.phase_label.to_string(), style));
        spans.push(Span::styled(status.state_symbol.to_string(), style));
    }
    let line = Line::from(spans);
    (line.width() <= width).then_some(line)
}

fn next_lines(header: &EngagementHeaderModel, width: usize) -> Vec<Line<'static>> {
    let body = if width >= 100 || header.next_tools.is_empty() {
        header.next_action.clone()
    } else {
        header
            .next_action
            .split_once(" — ")
            .map(|(head, _)| head.to_string())
            .unwrap_or_else(|| header.next_action.clone())
    };
    wrap_text(&body, width.saturating_sub(8).max(16))
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| {
            let lead = if index == 0 {
                Span::styled(" ▸ NEXT ", theme::warn())
            } else {
                Span::raw("        ")
            };
            Line::from(vec![lead, Span::styled(chunk, theme::primary())])
        })
        .collect()
}

fn command_hint_line(hints: &[WorkbenchHint], width: usize) -> Line<'static> {
    let mut spans = vec![Span::raw(" ")];
    let mut used = 1;
    for hint in hints {
        let atom = format!("{} {}", hint.verb, hint.label);
        let separator = usize::from(used > 1) * 3;
        let atom_width = display_width(&atom);
        if used + separator + atom_width > width {
            continue;
        }
        if separator > 0 {
            spans.push(Span::styled(" · ", theme::subtle()));
        }
        spans.push(Span::styled(atom, theme::muted()));
        used += separator + atom_width;
    }
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;
    use std::time::{Duration, Instant};

    #[test]
    fn reduced_motion_freezes_live_pulse_but_keeps_elapsed_redraws_due() {
        let _theme = theme::scoped_theme_for_test(theme::ThemeConfig {
            reduced_motion: true,
            color_depth: theme::ColorDepth::TrueColor,
            ..theme::ThemeConfig::default()
        });
        assert!(!live_pulse_on(), "reduced motion must freeze LIVE styling");

        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_running_tool_for_test("context:build");
        app.ui_mut().set_spinner_phase_for_test(7);
        let started_at = Instant::now();

        assert!(app.tick_at(started_at));
        assert_eq!(app.ui().spinner_phase(), 0);
        assert!(!app.tick_at(started_at + Duration::from_millis(999)));
        assert!(app.tick_at(started_at + Duration::from_secs(1)));
        assert_eq!(
            app.ui().spinner_phase(),
            0,
            "elapsed redraws must not restart animation"
        );
    }
}
