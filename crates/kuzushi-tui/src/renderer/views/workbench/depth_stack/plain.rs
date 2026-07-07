//! Plain / non-TTY projection of the depth stack (mode parity). Text dividers
//! stand in for the bordered panes, reusing the same row/line builders so TTY
//! and scripted output stay in lockstep.

use super::parts::{breadcrumb, line_muted, line_subtle, selected_alias, worklist_row};
use super::render::{drawer_body, ladder_lines, ladder_title, record_view};
use super::widgets::{elide, key_rail_line, Elide};
use crate::app::{WorkbenchDepth, WorkbenchNav};
use crate::renderer::shared::{blank, divider};
use crate::ui_view_models::WorkbenchModel;
use ratatui::text::Line;

pub(crate) fn workbench_depth_lines(
    nav: &WorkbenchNav,
    model: &WorkbenchModel,
    width: u16,
) -> Vec<Line<'static>> {
    let mut lines = vec![breadcrumb(nav, model), blank()];
    match nav.depth {
        WorkbenchDepth::List => append_list_plain(&mut lines, model, width),
        WorkbenchDepth::Finding => append_finding_plain(&mut lines, nav, model, width),
        WorkbenchDepth::Record => append_record_plain(&mut lines, nav, model, width),
    }
    lines.push(blank());
    lines.push(key_rail_line(nav));
    lines
}

fn append_list_plain(lines: &mut Vec<Line<'static>>, model: &WorkbenchModel, width: u16) {
    lines.push(divider(
        &format!("FINDINGS · {}", model.findings.len()),
        width,
    ));
    if model.findings.is_empty() {
        lines.push(line_subtle("no findings — run scan".to_string()));
        return;
    }
    let inner = width as usize;
    for (index, row) in model.findings.iter().enumerate() {
        lines.push(worklist_row(row, index == model.selected, inner));
    }
}

fn append_finding_plain(
    lines: &mut Vec<Line<'static>>,
    nav: &WorkbenchNav,
    model: &WorkbenchModel,
    width: u16,
) {
    let inner = width as usize;
    lines.push(divider(
        &format!("SELECTED · {}", selected_alias(model)),
        width,
    ));
    lines.push(line_muted(elide(
        &selected_title(model),
        Elide::Prose,
        inner,
    )));
    lines.push(blank());
    lines.push(divider(&ladder_title(model), width));
    lines.extend(ladder_lines(model, nav, inner));
    lines.push(blank());
    lines.push(divider(&format!("DRAWER · {}", nav.tab.label()), width));
    // Full log length as the window budget so plain output prints every line
    // (no head-tail elision when there is room to show it all).
    lines.extend(drawer_body(
        nav,
        model,
        inner,
        model.drawer.log.len().max(1),
    ));
}

fn append_record_plain(
    lines: &mut Vec<Line<'static>>,
    nav: &WorkbenchNav,
    model: &WorkbenchModel,
    width: u16,
) {
    let (title, body) = record_view(nav, model, width as usize);
    lines.push(divider(&title, width));
    lines.extend(body);
}

fn selected_title(model: &WorkbenchModel) -> String {
    model
        .findings
        .get(model.selected)
        .map(|row| row.title.clone())
        .unwrap_or_else(|| "no finding selected".to_string())
}
