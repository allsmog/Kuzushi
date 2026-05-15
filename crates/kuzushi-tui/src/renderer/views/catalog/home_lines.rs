use super::*;
use crate::ui_view_models::{home_cockpit_model, HomeArtifactRow, HomeCockpitModel};

pub(crate) fn home_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let model = home_cockpit_model(app);
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider(model.title, area.width));
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

fn append_home_summary(lines: &mut Vec<Line<'static>>, model: &HomeCockpitModel, width: u16) {
    for row in &model.summary_rows {
        lines.push(detail(&row.cells[0], &row.cells[1]));
    }
    if let Some(surface) = &model.attack_surface {
        lines.push(attack_surface_risk_line(surface, width));
    }
}

fn append_home_rail(lines: &mut Vec<Line<'static>>, model: &HomeCockpitModel, area: Rect) {
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
