use super::*;
use crate::ui_view_models::ScanPhaseModel;
use ratatui::layout::{Constraint, Direction, Layout};

mod content;
mod format;
mod study;

use content::{
    compact_summary_lines, engine_lines, finding_delta_lines, receipt_lines, render_engines,
    render_findings, render_receipt, render_scope, scope_lines,
};

const GRID_MIN_WIDTH: u16 = 78;
const COMBINED_MAX_WIDTH: u16 = WorkbenchPage::SCAN_GRID_MIN_COLUMNS - 1;
const COMBINED_MIN_HEIGHT: u16 = WorkbenchPage::SCAN_GRID_MIN_BODY_ROWS;

pub(super) fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ScanPhaseModel,
    state: PhaseRenderState,
) {
    if let Some(pane) = state.surface {
        render_scan_pane(frame, area, model, state, pane);
        return;
    }
    if area.width <= COMBINED_MAX_WIDTH || area.height < COMBINED_MIN_HEIGHT {
        render_combined(frame, area, model, state);
        return;
    }
    if area.width >= GRID_MIN_WIDTH {
        render_grid(frame, area, model, state);
    } else {
        render_stack(frame, area, model, state);
    }
}

pub(super) fn plain_lines(model: &ScanPhaseModel, width: usize) -> Vec<Line<'static>> {
    if model.study.is_some() {
        return study::plain_lines(model, width);
    }
    let mut lines = divider_lines("SCOPE / PLAN", scope_lines(model, width), width);
    lines.extend(divider_lines(
        "ENGINE OUTCOMES",
        engine_lines(model, width),
        width,
    ));
    lines.extend(divider_lines(
        "FINDING / ARTIFACT DELTA",
        finding_delta_lines(model, width),
        width,
    ));
    lines.extend(divider_lines(
        "SCAN RECEIPT",
        receipt_lines(model, width),
        width,
    ));
    lines
}

fn render_grid(frame: &mut Frame<'_>, area: Rect, model: &ScanPhaseModel, state: PhaseRenderState) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    let top = split_row(rows[0]);
    let bottom = split_row(rows[1]);
    render_scope(frame, top[0], model, state);
    render_engines(frame, top[1], model, state);
    render_findings(frame, bottom[0], model, state);
    render_receipt(frame, bottom[1], model, state);
}

fn render_stack(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ScanPhaseModel,
    state: PhaseRenderState,
) {
    let panes = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);
    render_scope(frame, panes[0], model, state);
    render_engines(frame, panes[1], model, state);
    render_findings(frame, panes[2], model, state);
    render_receipt(frame, panes[3], model, state);
}

fn split_row(area: Rect) -> std::rc::Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area)
}

fn render_combined(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ScanPhaseModel,
    state: PhaseRenderState,
) {
    let width = area.width.saturating_sub(2) as usize;
    render_lines_pane(
        frame,
        area,
        "SCAN · recorded result",
        compact_summary_lines(model, width),
        PhaseSurfaceId::ScanEngines,
        state,
    );
}

fn render_scan_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ScanPhaseModel,
    state: PhaseRenderState,
    surface: PhaseSurfaceId,
) {
    match surface {
        PhaseSurfaceId::ScanScope => render_scope(frame, area, model, state),
        PhaseSurfaceId::ScanEngines => render_engines(frame, area, model, state),
        PhaseSurfaceId::ScanDelta => render_findings(frame, area, model, state),
        PhaseSurfaceId::ScanReceipt => render_receipt(frame, area, model, state),
        _ => render_engines(frame, area, model, state),
    }
}
