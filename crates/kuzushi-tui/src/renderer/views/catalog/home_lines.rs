use super::*;
use crate::ui_view_models::{home_cockpit_model, HomeArtifactRow, HomeCockpitModel};

pub(crate) fn home_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let model = home_cockpit_model(app);
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("HOME", area.width));
    append_home_summary(&mut lines, &model, area.width);
    lines.push(blank());
    lines.push(next_action_line(&model.next_action, area.width as usize));
    lines.push(blank());
    append_home_rail(&mut lines, &model, area);
    lines.push(blank());
    lines.push(command_list_line(
        &[
            "modules",
            "recommend",
            "quickstart",
            "scan .",
            "findings",
            "runs",
        ],
        area.width as usize,
    ));
    lines
}

fn append_home_summary(lines: &mut Vec<Line<'static>>, model: &HomeCockpitModel, width: u16) {
    lines.push(detail("target", &model.target));
    lines.push(detail("latest run", &model.latest_run));
    lines.push(detail("run status", &model.run_status));
    lines.push(detail("modules", &model.module_count.to_string()));
    lines.push(detail("findings", &model.finding_count.to_string()));
    if let Some(surface) = &model.attack_surface {
        lines.push(attack_surface_risk_line(surface, width));
    }
}

fn append_home_rail(lines: &mut Vec<Line<'static>>, model: &HomeCockpitModel, area: Rect) {
    lines.push(muted(
        "rails: ✓ recorded → ○ placeholder ⚠ failed ■ missing ◆ partial",
    ));
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
