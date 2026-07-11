use super::*;
use crate::renderer::views::scene::diagrams::attack_path_lines;
use crate::ui_view_models::{ConfirmPhaseModel, FindingDetailModel};
use ratatui::layout::{Constraint, Direction, Layout};

mod proof;

use proof::{compact_proof_lines, finding_header_lines, proof_lines, proof_title};

const REFERENCE_LAYOUT_MIN_WIDTH: u16 = 100;

pub(super) fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ConfirmPhaseModel,
    state: PhaseRenderState,
) {
    if let Some(pane) = state.zoom {
        render_zoomed(frame, area, model, state, pane);
        return;
    }
    let Some(finding) = model.finding.as_ref() else {
        render_empty(frame, area, model, state);
        return;
    };
    if area.width >= REFERENCE_LAYOUT_MIN_WIDTH {
        render_reference(frame, area, model, finding, state);
    } else {
        render_compact(frame, area, model, finding, state);
    }
}

fn render_empty(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ConfirmPhaseModel,
    state: PhaseRenderState,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4.min(area.height)),
            Constraint::Percentage(28),
            Constraint::Min(0),
        ])
        .split(area);
    render_lines_pane(
        frame,
        rows[0],
        "FINDING",
        empty_selection_lines(model),
        WorkbenchPane::Source,
        state,
    );
    render_attack_path(frame, rows[1], model, state);
    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(68), Constraint::Percentage(32)])
        .split(rows[2]);
    render_ladder(frame, bottom[0], model, state);
    render_empty_proof(frame, bottom[1], model, state);
}

fn render_empty_finding(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ConfirmPhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "FINDING",
        empty_selection_lines(model),
        WorkbenchPane::Source,
        state,
    );
}

fn render_empty_proof(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ConfirmPhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "PROOF",
        empty_selection_lines(model),
        WorkbenchPane::Details,
        state,
    );
}

fn empty_selection_lines(model: &ConfirmPhaseModel) -> Vec<Line<'static>> {
    empty_state_panel(
        "no finding selected",
        &[model.empty_hint.unwrap_or("select a finding in Hunt")],
        &[("2", "open Hunt and choose a finding")],
    )
}

pub(super) fn plain_lines(model: &ConfirmPhaseModel, width: usize) -> Vec<Line<'static>> {
    let Some(finding) = model.finding.as_ref() else {
        let mut lines = divider_lines("FINDING", empty_selection_lines(model), width);
        lines.extend(divider_lines(
            "ATTACK PATH",
            attack_path_lines(width, &model.attack_path),
            width,
        ));
        lines.extend(divider_lines(
            "DATA-FLOW LADDER",
            super::super::phase_diagrams::flow_ladder_lines(&model.attack_path, width),
            width,
        ));
        lines.extend(divider_lines("PROOF", empty_selection_lines(model), width));
        return lines;
    };
    let mut lines = divider_lines("FINDING", finding_header_lines(finding, width), width);
    lines.extend(divider_lines(
        "ATTACK PATH",
        attack_path_lines(width, &model.attack_path),
        width,
    ));
    lines.extend(divider_lines(
        "DATA-FLOW LADDER",
        super::super::phase_diagrams::flow_ladder_lines(&model.attack_path, width),
        width,
    ));
    lines.extend(divider_lines(
        proof_title(model.proof.as_ref()),
        proof_lines(model.proof.as_ref(), finding, width),
        width,
    ));
    lines
}

fn render_reference(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ConfirmPhaseModel,
    finding: &FindingDetailModel,
    state: PhaseRenderState,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3.min(area.height)),
            Constraint::Length(8.min(area.height.saturating_sub(3))),
            Constraint::Min(0),
        ])
        .split(area);
    render_finding_header(frame, rows[0], finding, state);
    render_attack_path(frame, rows[1], model, state);
    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(68), Constraint::Percentage(32)])
        .split(rows[2]);
    render_ladder(frame, bottom[0], model, state);
    render_proof(frame, bottom[1], model, finding, state);
}

fn render_compact(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ConfirmPhaseModel,
    finding: &FindingDetailModel,
    state: PhaseRenderState,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(18),
            Constraint::Percentage(27),
            Constraint::Percentage(32),
            Constraint::Percentage(23),
        ])
        .split(area);
    render_finding_header(frame, rows[0], finding, state);
    render_attack_path(frame, rows[1], model, state);
    render_ladder(frame, rows[2], model, state);
    render_proof(frame, rows[3], model, finding, state);
}

fn render_zoomed(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ConfirmPhaseModel,
    state: PhaseRenderState,
    pane: WorkbenchPane,
) {
    let Some(finding) = model.finding.as_ref() else {
        match pane {
            WorkbenchPane::Source => render_empty_finding(frame, area, model, state),
            WorkbenchPane::Center => render_attack_path(frame, area, model, state),
            WorkbenchPane::Findings => render_ladder(frame, area, model, state),
            WorkbenchPane::Details => render_empty_proof(frame, area, model, state),
        }
        return;
    };
    match pane {
        WorkbenchPane::Source => render_finding_header(frame, area, finding, state),
        WorkbenchPane::Center => render_attack_path(frame, area, model, state),
        WorkbenchPane::Findings => render_ladder(frame, area, model, state),
        WorkbenchPane::Details => render_proof(frame, area, model, finding, state),
    }
}

fn render_finding_header(
    frame: &mut Frame<'_>,
    area: Rect,
    finding: &FindingDetailModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "FINDING",
        finding_header_lines(finding, area.width.saturating_sub(2) as usize),
        WorkbenchPane::Source,
        state,
    );
}

fn render_attack_path(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ConfirmPhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "ATTACK PATH",
        attack_path_lines(area.width.saturating_sub(2) as usize, &model.attack_path),
        WorkbenchPane::Center,
        state,
    );
}

fn render_ladder(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ConfirmPhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "DATA-FLOW LADDER",
        super::super::phase_diagrams::flow_ladder_lines(
            &model.attack_path,
            area.width.saturating_sub(2) as usize,
        ),
        WorkbenchPane::Findings,
        state,
    );
}

fn render_proof(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ConfirmPhaseModel,
    finding: &FindingDetailModel,
    state: PhaseRenderState,
) {
    let width = area.width.saturating_sub(2) as usize;
    let lines = if area.height <= 8 {
        compact_proof_lines(model.proof.as_ref(), finding, width)
    } else {
        proof_lines(model.proof.as_ref(), finding, width)
    };
    render_lines_pane(
        frame,
        area,
        proof_title(model.proof.as_ref()),
        lines,
        WorkbenchPane::Details,
        state,
    );
}
