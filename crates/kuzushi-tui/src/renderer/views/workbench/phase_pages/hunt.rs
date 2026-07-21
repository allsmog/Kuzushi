use super::*;
use crate::ui_view_models::{NextScansState, ReviewPhaseModel};
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
    let plan = next_plan_lines(&model.next_plan, width);
    if !plan.is_empty() {
        lines.extend(divider_lines("NEXT INVESTIGATION PLAN", plan, width));
    }
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
        PhaseSurfaceId::ReviewNextPlan => render_next_plan_drawer(frame, area, model, state),
        _ => render_review_list(frame, area, model, state),
    }
}

/// The scan-complete recommendation moment: the recommender proposes
/// follow-up passes with their evidence, and Enter merely drafts the command
/// — Kuzushi recommends, the operator authorizes.
fn render_next_plan_drawer(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ReviewPhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "NEXT INVESTIGATION PLAN · Enter run plan · Tab skip",
        next_plan_lines(&model.next_plan, area.width.saturating_sub(2) as usize),
        PhaseSurfaceId::ReviewNextPlan,
        state,
    );
}

fn next_plan_lines(next_plan: &NextScansState, width: usize) -> Vec<Line<'static>> {
    let NextScansState::Ready(rows) = next_plan else {
        return Vec::new();
    };
    if rows.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![Line::styled(
        fit(
            &format!(
                "Coverage and staleness evidence recommends {} follow-up pass(es):",
                rows.len()
            ),
            width,
        ),
        theme::muted(),
    )];
    lines.extend(rows.iter().map(|row| {
        Line::styled(
            fit(
                &format!(
                    "▸ {} {} — {} · {}",
                    row.phase, row.scope, row.reason, row.evidence
                ),
                width,
            ),
            theme::primary(),
        )
    }));
    lines.push(Line::styled(
        fit(
            "Enter drafts `next` into the prompt — nothing runs until you submit it",
            width,
        ),
        theme::subtle(),
    ));
    lines
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui_view_models::NextScanRow;

    fn text(lines: &[Line<'_>]) -> String {
        lines
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn next_plan_lines_state_the_evidence_and_the_authorization_boundary() {
        let ready = NextScansState::Ready(vec![NextScanRow {
            scope: "root".to_string(),
            phase: "scan".to_string(),
            reason: "changed".to_string(),
            evidence: "14 files changed since a1b2c3d4".to_string(),
        }]);

        let rendered = text(&next_plan_lines(&ready, 100));

        assert!(rendered.contains("recommends 1 follow-up pass(es)"));
        assert!(rendered.contains("▸ scan root — changed · 14 files changed since a1b2c3d4"));
        assert!(rendered.contains("nothing runs until you submit"));
    }

    #[test]
    fn pending_or_empty_recommendations_render_no_plan_card_content() {
        assert!(next_plan_lines(&NextScansState::Pending, 80).is_empty());
        assert!(next_plan_lines(&NextScansState::Ready(Vec::new()), 80).is_empty());
        assert!(next_plan_lines(&NextScansState::Unavailable("boom".to_string()), 80).is_empty());
    }
}
