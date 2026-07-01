use super::*;
use crate::ui_view_models::{
    home_cockpit_model, HomeArtifactRow, HomeCockpitModel, JourneyModel, JourneyPhaseTone,
};

pub(crate) fn home_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let model = home_cockpit_model(app);
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider(model.title, area.width));
    if let Some(journey) = &model.journey {
        lines.push(journey_rail_line(journey));
    }
    append_home_summary(&mut lines, &model, area.width);
    lines.push(blank());
    lines.push(next_action_line(&model.next_action, area.width as usize));
    lines.push(blank());
    append_home_rail(&mut lines, &model, area);
    lines.push(blank());
    lines.push(command_list_line(
        &model.command_labels,
        area.width as usize,
    ));
    lines
}

/// The engagement spine: `組 map ✓ · 崩 hunt ● · 作 confirm ○ · 掛 fix ○`.
/// Always one line — four short words fit any terminal the footer fits.
fn journey_rail_line(journey: &JourneyModel) -> Line<'static> {
    let mut spans = vec![Span::raw(" ")];
    for (index, status) in journey.phases.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled(" · ", theme::subtle()));
        }
        let style = journey_phase_tone_style(status.tone);
        spans.push(Span::styled(status.phase_label, style));
        spans.push(Span::styled(status.state_symbol.to_string(), style));
    }
    Line::from(spans)
}

fn journey_phase_tone_style(tone: JourneyPhaseTone) -> Style {
    match tone {
        JourneyPhaseTone::Success => theme::success(),
        JourneyPhaseTone::Warn => theme::warn(),
        JourneyPhaseTone::Danger => theme::danger(),
        JourneyPhaseTone::Muted => theme::muted(),
        JourneyPhaseTone::Subtle => theme::subtle(),
    }
}

fn append_home_summary(lines: &mut Vec<Line<'static>>, model: &HomeCockpitModel, width: u16) {
    for row in &model.summary_rows {
        lines.push(detail(&row.cells[0], &row.cells[1]));
    }
    if let Some(surface) = &model.attack_surface {
        lines.push(attack_surface_risk_line(surface, width));
    }
}

fn append_home_rail(lines: &mut Vec<Line<'static>>, model: &HomeCockpitModel, area: Rect) {
    // The view model decides whether to collapse the rail (fresh workspace) or
    // show the full legend + per-artifact rows; the renderer just paints it.
    if let Some(summary) = &model.rail_summary {
        lines.push(muted(summary));
        return;
    }
    lines.push(muted(model.rail_legend));
    for artifact in &model.artifacts {
        lines.push(rail_row(artifact, area.width));
    }
}

fn rail_row(artifact: &HomeArtifactRow, width: u16) -> Line<'static> {
    let [glyph, label, state, path] = &artifact.cells;
    let path_width = (width as usize).saturating_sub(38).max(24);
    row(&[
        pad(glyph, 3),
        pad(label, 12),
        pad(state, 12),
        fit(path, path_width),
    ])
}
