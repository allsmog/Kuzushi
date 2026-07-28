use super::*;
use crate::renderer::views::scene::diagram::{DfdDiagram, TreeDiagram};
use crate::ui_view_models::FixPhaseModel;
use ratatui::layout::{Constraint, Direction, Layout};

mod diagrams;
mod remediation;
mod report;

use diagrams::{attack_tree_lines, dfd_lines};
use remediation::{compact_remediation_lines, remediation_lines};
use report::breakdown_lines;

const REFERENCE_LAYOUT_MIN_WIDTH: u16 = 120;
const GRID_LAYOUT_MIN_WIDTH: u16 = 80;

pub(super) fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &FixPhaseModel,
    state: PhaseRenderState,
) {
    if let Some(pane) = state.surface {
        render_zoomed(frame, area, model, state, pane);
        return;
    }
    if area.width < GRID_LAYOUT_MIN_WIDTH || area.height < WorkbenchPage::FIX_DIAGRAM_MIN_BODY_ROWS
    {
        render_compact(frame, area, model, state);
    } else if area.width >= REFERENCE_LAYOUT_MIN_WIDTH {
        render_reference(frame, area, model, state);
    } else {
        render_grid(frame, area, model, state);
    }
}

pub(super) fn plain_lines(model: &FixPhaseModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = divider_lines("BREAKDOWN REPORT", breakdown_lines(model, width), width);
    lines.extend(divider_lines(
        "ATTACK TREE",
        attack_tree_lines(&model.attack_tree, width),
        width,
    ));
    lines.extend(divider_lines("DFD", dfd_lines(&model.dfd, width), width));
    lines.extend(divider_lines(
        "REMEDIATION",
        remediation_lines(model, width),
        width,
    ));
    lines.extend(divider_lines(
        "VERIFICATION",
        verification_lines(model, width),
        width,
    ));
    lines
}

fn render_reference(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &FixPhaseModel,
    state: PhaseRenderState,
) {
    let rows = phase_rows(area, 6, 62);
    render_breakdown(frame, rows[0], model, state);
    let diagrams = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(rows[1]);
    render_attack_tree(frame, diagrams[0], model, state);
    render_dfd(frame, diagrams[1], model, state);
    render_remediation(frame, rows[2], model, state);
}

fn render_grid(frame: &mut Frame<'_>, area: Rect, model: &FixPhaseModel, state: PhaseRenderState) {
    let rows = phase_rows(area, 5, 52);
    render_breakdown(frame, rows[0], model, state);
    let diagrams = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);
    render_attack_tree(frame, diagrams[0], model, state);
    render_dfd(frame, diagrams[1], model, state);
    render_remediation(frame, rows[2], model, state);
}

fn phase_rows(area: Rect, report_height: u16, diagram_percent: u16) -> std::rc::Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(report_height.min(area.height)),
            Constraint::Percentage(diagram_percent),
            Constraint::Min(6),
        ])
        .split(area)
}

fn render_compact(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &FixPhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "FIX · BREAKDOWN REPORT",
        compact_lines(model, area.width.saturating_sub(2) as usize),
        PhaseSurfaceId::FixAttackTree,
        state,
    );
}

fn compact_lines(model: &FixPhaseModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = breakdown_lines(model, width);
    append_compact_section(
        &mut lines,
        "ATTACK TREE",
        attack_tree_lines(&model.attack_tree, width),
        width,
    );
    append_compact_section(&mut lines, "DFD", dfd_lines(&model.dfd, width), width);
    lines.extend(divider_lines(
        "REMEDIATION",
        compact_remediation_lines(model, width),
        width,
    ));
    lines
}

fn append_compact_section(
    lines: &mut Vec<Line<'static>>,
    title: &str,
    body: Vec<Line<'static>>,
    width: usize,
) {
    lines.push(divider(title, width as u16));
    let body_rows = if width < 80 { 1 } else { 2 };
    lines.extend(body.into_iter().take(body_rows));
}

fn render_zoomed(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &FixPhaseModel,
    state: PhaseRenderState,
    surface: PhaseSurfaceId,
) {
    match surface {
        PhaseSurfaceId::FixAttackTree => render_attack_tree(frame, area, model, state),
        PhaseSurfaceId::FixDfd => render_dfd(frame, area, model, state),
        PhaseSurfaceId::FixRemediation => render_remediation(frame, area, model, state),
        PhaseSurfaceId::FixCandidate => render_lines_pane(
            frame,
            area,
            "KUZUSHI · BREAKDOWN REPORT",
            breakdown_lines(model, area.width.saturating_sub(2) as usize),
            PhaseSurfaceId::FixCandidate,
            state,
        ),
        PhaseSurfaceId::FixVerification => render_verification_column(frame, area, model, state),
        _ => render_remediation(frame, area, model, state),
    }
}

fn render_breakdown(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &FixPhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "KUZUSHI · BREAKDOWN REPORT",
        breakdown_lines(model, area.width.saturating_sub(2) as usize),
        PhaseSurfaceId::FixCandidate,
        state,
    );
}

fn render_attack_tree(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &FixPhaseModel,
    state: PhaseRenderState,
) {
    render_diagram_pane(
        frame,
        area,
        "ATTACK TREE",
        PhaseSurfaceId::FixAttackTree,
        state,
        TreeDiagram {
            model: model.attack_tree.clone(),
        },
    );
}

fn render_dfd(frame: &mut Frame<'_>, area: Rect, model: &FixPhaseModel, state: PhaseRenderState) {
    render_diagram_pane(
        frame,
        area,
        "DFD",
        PhaseSurfaceId::FixDfd,
        state,
        DfdDiagram {
            model: model.dfd.clone(),
            // The Fix pane embeds the diagram without an inspector cursor.
            selection: None,
            detail_scroll: 0,
        },
    );
}

fn render_remediation(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &FixPhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "REMEDIATION",
        remediation_lines(model, area.width.saturating_sub(2) as usize),
        PhaseSurfaceId::FixRemediation,
        state,
    );
}

/// The patch verification ladder: safe-patch gate, build/tests, and the
/// proof-must-fail re-validation, with reason-coded deferral surfaced as a
/// durable peer outcome rather than a skipped state.
fn render_verification_column(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &FixPhaseModel,
    state: PhaseRenderState,
) {
    let width = area.width.saturating_sub(2) as usize;
    render_lines_pane(
        frame,
        area,
        "VERIFICATION",
        verification_lines(model, width),
        PhaseSurfaceId::FixVerification,
        state,
    );
}

fn verification_lines(model: &FixPhaseModel, width: usize) -> Vec<Line<'static>> {
    use crate::ui_view_models::RemediationLifecycleStage as Stage;
    let remediation = &model.remediation;
    let staged = model.patch.is_some() || remediation.stage != Stage::NotDrafted;
    let applied = matches!(
        remediation.stage,
        Stage::Applied
            | Stage::ReverifyRunning
            | Stage::Verified
            | Stage::StillVulnerable
            | Stage::NotRediscovered
            | Stage::ChangedSinceApply
    );
    let reverified = remediation.stage == Stage::Verified;
    let rung = |done: bool, label: &str| {
        let mark = if done { "✓" } else { "○" };
        let style = if done {
            theme::success()
        } else {
            theme::muted()
        };
        Line::styled(fit(&format!("{mark} {label}"), width), style)
    };
    let mut lines = vec![
        rung(staged, "patch drafted through the safe-patch gate"),
        rung(applied, "applied · build and tests recorded"),
        rung(
            reverified,
            "proof fails after patch (reverify verified absence)",
        ),
    ];
    if let Some(command) = remediation.reverify_command.as_deref() {
        lines.push(Line::styled(
            fit(&format!("▸ {command}"), width),
            theme::accent(),
        ));
    }
    if let Some(detail) = remediation.detail.as_deref() {
        lines.push(Line::styled(fit(detail, width), theme::muted()));
    }
    lines.push(Line::styled(
        fit("defer with a reason code records a durable outcome", width),
        theme::muted(),
    ));
    lines
}
