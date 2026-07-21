use super::*;
use crate::ui_view_models::ReviewPhaseModel;
use ratatui::layout::{Constraint, Direction, Layout};

const SIDE_BY_SIDE_MIN_WIDTH: u16 = 78;

pub(super) fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    _app: &ShellApp,
    model: &ReviewPhaseModel,
    state: PhaseRenderState,
) {
    if let Some(pane) = state.surface {
        render_review_pane(frame, area, model, state, pane);
        return;
    }
    let panes = if area.width >= SIDE_BY_SIDE_MIN_WIDTH {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(44), Constraint::Percentage(56)])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
            .split(area)
    };
    render_review_list(frame, panes[0], model, state);
    render_review_detail(frame, panes[1], model, state);
}

pub(super) fn plain_lines(model: &ReviewPhaseModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = divider_lines("FINDINGS", review_lines(model, width, u16::MAX), width);
    lines.extend(divider_lines(
        "SELECTED FINDING",
        review_detail_lines(model, width),
        width,
    ));
    lines
}

fn render_review_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ReviewPhaseModel,
    state: PhaseRenderState,
    surface: PhaseSurfaceId,
) {
    match surface {
        PhaseSurfaceId::ReviewDetail => render_review_detail(frame, area, model, state),
        _ => render_review_list(frame, area, model, state),
    }
}

fn render_review_list(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ReviewPhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        format!("FINDINGS · {}", model.review.visible_count),
        review_lines(
            model,
            area.width.saturating_sub(2) as usize,
            area.height.saturating_sub(2),
        ),
        PhaseSurfaceId::ReviewQueue,
        state,
    );
}

fn review_lines(model: &ReviewPhaseModel, width: usize, height: u16) -> Vec<Line<'static>> {
    let mut lines = selection_disclosure_lines(model.selection_disclosure.as_ref(), width);
    let disclosure_rows = lines.len().min(u16::MAX as usize) as u16;
    lines.extend(super::super::panes::review_queue_pane_lines(
        &model.review,
        Rect::new(
            0,
            0,
            width.min(u16::MAX as usize) as u16,
            height.saturating_sub(disclosure_rows),
        ),
    ));
    lines
}

fn render_review_detail(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ReviewPhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "SELECTED FINDING · Enter prove · z heatmap",
        review_detail_lines(model, area.width.saturating_sub(2) as usize),
        PhaseSurfaceId::ReviewDetail,
        state,
    );
}

fn review_detail_lines(model: &ReviewPhaseModel, width: usize) -> Vec<Line<'static>> {
    let Some(finding) = model.finding.as_ref() else {
        return empty_state_panel(
            "no finding selected",
            &["move through FINDINGS to inspect a result"],
            &[("Enter", "open selected finding in Prove")],
        );
    };
    let mut lines = proof_ladder_lines(finding, width);
    lines.extend(super::super::detail_pane::detail_pane_lines(
        &Some(finding.clone()),
        width,
        None,
    ));
    lines
}

/// A finding is a claim moving through an adversarial ladder. The strip makes
/// the proof state visually obvious — including the refuted terminal state,
/// which stays on screen instead of hiding behind a filter.
fn proof_ladder_lines(
    finding: &crate::ui_view_models::FindingDetailModel,
    width: usize,
) -> Vec<Line<'static>> {
    use crate::ui_view_models::ProofTier;
    if finding.proof_tier == ProofTier::Rejected {
        return vec![Line::styled(
            fit(
                &format!(
                    "✖ REFUTED · {} — kept visible for the record",
                    finding.decision
                ),
                width,
            ),
            theme::danger(),
        )];
    }
    let reached = match finding.proof_tier {
        ProofTier::Suspected => 1,
        ProofTier::StaticLinked => 2,
        ProofTier::RuntimeVerified => 3,
        ProofTier::Rejected => 0,
    };
    let proven = reached == 3
        && (finding
            .lifecycle_status
            .to_ascii_lowercase()
            .contains("patched")
            || finding
                .runtime_verification
                .to_ascii_lowercase()
                .contains("reverified"));
    let rungs = ["candidate", "corroborated", "reproduced", "proven"];
    let mut spans = Vec::new();
    for (index, rung) in rungs.iter().enumerate() {
        let lit = index < reached || (index == 3 && proven);
        let mark = if lit { "●" } else { "○" };
        let style = if lit {
            theme::success()
        } else {
            theme::muted()
        };
        if index > 0 {
            spans.push(Span::styled(" ─ ", theme::muted()));
        }
        spans.push(Span::styled(format!("{mark} {rung}"), style));
    }
    vec![Line::from(spans)]
}
