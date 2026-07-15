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
    lines.extend(context_header_lines(header, width));
    lines.extend(result_card_lines(header.result_card.as_ref(), width));
    lines.extend(command_hint_lines(header, hints, width));
    lines
}

fn context_header_lines(header: &EngagementHeaderModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.extend(phase_rail_line(&header.phase_rail, width));
    lines.extend(
        header
            .finding_filter
            .as_deref()
            .map(|filter| finding_filter_line(filter, width)),
    );
    lines.extend(next_header_lines(header, width));
    lines
}

fn next_header_lines(header: &EngagementHeaderModel, width: usize) -> Vec<Line<'static>> {
    if uses_compact_result_header(header, width) {
        return Vec::new();
    }
    next_lines(header, width)
}

fn command_hint_lines(
    header: &EngagementHeaderModel,
    hints: &[WorkbenchHint],
    width: usize,
) -> Vec<Line<'static>> {
    if header.result_card.is_some() || width < 80 || hints.is_empty() {
        return Vec::new();
    }
    vec![command_hint_line(hints, width)]
}

fn uses_compact_result_header(header: &EngagementHeaderModel, width: usize) -> bool {
    width < 50 && header.result_card.is_some()
}

fn result_card_lines(
    card: Option<&crate::ui_view_models::PhaseResultCardModel>,
    width: usize,
) -> Vec<Line<'static>> {
    let Some(card) = card else {
        return Vec::new();
    };
    let mut lines = vec![Line::from(vec![
        Span::styled(" RESULT ", theme::warn()),
        Span::styled(
            fit(
                &format!("{} · attempt {}", card.outcome, card.attempt_id),
                width.saturating_sub(8),
            ),
            theme::primary(),
        ),
    ])];
    lines.extend(result_detail_lines(card, width));
    lines.push(Line::from(Span::styled(
        fit(&format!("  {}", card.control_hint), width),
        theme::accent(),
    )));
    if width >= 80 {
        lines.push(Line::from(Span::styled(
            fit(&format!("  next: {}", card.recommended), width),
            theme::label(),
        )));
    }
    lines
}

fn result_detail_lines(
    card: &crate::ui_view_models::PhaseResultCardModel,
    width: usize,
) -> Vec<Line<'static>> {
    if width < 50 {
        return Vec::new();
    }
    let available = width.saturating_sub(3).max(16);
    wrap_text(&card.detail, available)
        .into_iter()
        .map(|text| Line::from(Span::styled(format!("  {text}"), theme::muted())))
        .collect()
}

fn finding_filter_line(filter: &str, width: usize) -> Line<'static> {
    Line::from(vec![
        Span::styled(" FILTER ", theme::warn()),
        Span::styled(
            fit(
                &format!("{filter} · clear: findings filter clear"),
                width.saturating_sub(8),
            ),
            theme::primary(),
        ),
    ])
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
        (
            format!("VIEW {}", header.phase.label()),
            mode_style(header.phase),
        ),
    ];
    if header
        .reality_phase
        .is_some_and(|reality| reality != header.phase)
    {
        let reality = header.reality_phase.expect("checked reality phase");
        atoms.push((format!("REALITY {}", reality.label()), theme::muted()));
    }
    atoms.extend([
        (format!("target {}", header.target), theme::label()),
        live_atom(header.live),
    ]);
    if header.cost_invalid {
        atoms.push(("cost invalid".to_string(), theme::danger()));
    } else if !header.cost_complete {
        atoms.push((
            format!("cost >=${:.2} incomplete", header.cost_usd),
            theme::warn(),
        ));
    } else if header.cost_usd > 0.0 {
        atoms.push((format!("cost ${:.2}", header.cost_usd), theme::primary()));
    }
    atoms.extend([
        (header.context.clone(), context_style(&header.context)),
        (format!("model {}", header.model), theme::muted()),
        (module_atom(&header.module), module_style(&header.module)),
    ]);
    atoms
}

fn mode_style(phase: kuzushi_core::WorkflowPhase) -> ratatui::style::Style {
    match phase {
        kuzushi_core::WorkflowPhase::Map => theme::mode_map(),
        kuzushi_core::WorkflowPhase::Scan => theme::mode_scan(),
        kuzushi_core::WorkflowPhase::Review => theme::mode_review(),
        kuzushi_core::WorkflowPhase::Prove => theme::mode_prove(),
        kuzushi_core::WorkflowPhase::Fix => theme::mode_fix(),
    }
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
mod tests;
