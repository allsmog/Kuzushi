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
    if area.width < REFERENCE_LAYOUT_MIN_WIDTH {
        render_empty_finding(frame, area, model, state);
        return;
    }
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
            Constraint::Length(4.min(area.height)),
            Constraint::Length(8.min(area.height.saturating_sub(4))),
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
    if model.attack_path.stages.is_empty() {
        render_compact_without_path(frame, area, model, finding, state);
        return;
    }
    let heights = compact_panel_heights(area.height);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(heights.finding),
            Constraint::Length(heights.attack_path),
            Constraint::Length(heights.ladder),
            Constraint::Min(0),
        ])
        .split(area);
    render_finding_header(frame, rows[0], finding, state);
    render_attack_path(frame, rows[1], model, state);
    render_ladder(frame, rows[2], model, state);
    render_proof(frame, rows[3], model, finding, state);
}

fn render_compact_without_path(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ConfirmPhaseModel,
    finding: &FindingDetailModel,
    state: PhaseRenderState,
) {
    let proof_rows = area.height.min(4);
    let remaining = area.height.saturating_sub(proof_rows);
    let path_rows = u16::from(remaining > 2);
    let finding_rows = remaining.saturating_sub(path_rows);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(finding_rows),
            Constraint::Length(path_rows),
            Constraint::Length(proof_rows),
        ])
        .split(area);
    render_finding_header(frame, rows[0], finding, state);
    render_missing_path_summary(frame, rows[1], model, state);
    render_proof(frame, rows[2], model, finding, state);
}

fn render_missing_path_summary(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ConfirmPhaseModel,
    state: PhaseRenderState,
) {
    let hint = model
        .attack_path
        .empty_hint
        .as_deref()
        .unwrap_or("not generated — run `taint-iris:hunt`");
    render_lines_pane(
        frame,
        area,
        "ATTACK PATH",
        vec![Line::styled(
            fit(hint, area.width.saturating_sub(2) as usize),
            theme::muted(),
        )],
        WorkbenchPane::Center,
        state,
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CompactPanelHeights {
    finding: u16,
    attack_path: u16,
    ladder: u16,
}

fn compact_panel_heights(height: u16) -> CompactPanelHeights {
    let finding = height.min(4);
    let proof_reserve = height.saturating_sub(finding).min(5);
    let diagram_rows = height.saturating_sub(finding + proof_reserve);
    CompactPanelHeights {
        finding,
        attack_path: diagram_rows.div_ceil(2),
        ladder: diagram_rows / 2,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui_view_models::SeverityTone;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn compact_layout_reserves_identity_and_proof_before_diagrams() {
        let heights = compact_panel_heights(12);

        assert_eq!(heights.finding, 4);
        assert_eq!(heights.attack_path + heights.ladder, 3);
        assert_eq!(
            12 - heights.finding - heights.attack_path - heights.ladder,
            5
        );
    }

    #[test]
    fn compact_empty_path_keeps_finding_identity_location_and_proof_action() {
        let model = compact_confirm_model();
        let backend = TestBackend::new(60, 12);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| render(frame, frame.area(), &model, PhaseRenderState::activity()))
            .unwrap();

        let rendered = buffer_text(terminal.backend().buffer());
        assert!(rendered.contains("F-0001"), "{rendered}");
        assert!(rendered.contains("Hardcoded credential"), "{rendered}");
        assert!(rendered.contains("src/config.rs:42"), "{rendered}");
        assert!(
            rendered.contains("decision: rejected false positive"),
            "{rendered}"
        );
        assert!(rendered.contains("verify F-0001"), "{rendered}");
        assert!(!rendered.contains("DATA-FLOW LADDER"), "{rendered}");
    }

    fn compact_confirm_model() -> ConfirmPhaseModel {
        let finding = FindingDetailModel {
            alias: Some("F-0001".to_string()),
            severity_tone: SeverityTone::High,
            severity_label: "high".to_string(),
            title: "Hardcoded credential".to_string(),
            location: "src/config.rs:42".to_string(),
            proof_marker: "?",
            proof_label: "signal-only".to_string(),
            lifecycle_status: "candidate".to_string(),
            static_proof_label: "signal-only".to_string(),
            runtime_explanation: "runtime verification has not run".to_string(),
            next_command: Some("verify F-0001".to_string()),
            decision: "rejected_false_positive".to_string(),
            ..FindingDetailModel::default()
        };
        ConfirmPhaseModel {
            finding: Some(finding),
            attack_path: crate::ui_view_models::TaintFlowPath {
                empty_hint: Some("not generated — run `taint-iris:hunt`".to_string()),
                ..Default::default()
            },
            proof: None,
            empty_hint: None,
        }
    }

    fn buffer_text(buffer: &ratatui::buffer::Buffer) -> String {
        (buffer.area.y..buffer.area.bottom())
            .map(|y| {
                (buffer.area.x..buffer.area.right())
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}
