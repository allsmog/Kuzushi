use super::*;
use crate::app::PhaseResultDetailRow;
use crate::ui_view_models::PhaseResultCardModel;
use kuzushi_core::run_lifecycle::RunCellRoleV1;

pub(super) fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ProvePhaseModel,
    card: &PhaseResultCardModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        result_title(model, card),
        lines(model, card, area.width.saturating_sub(2) as usize),
        PhaseSurfaceId::ProveResult,
        state,
    );
}

fn result_title(model: &ProvePhaseModel, card: &PhaseResultCardModel) -> String {
    match model
        .finding
        .as_ref()
        .and_then(|finding| finding.alias.as_deref())
    {
        Some(alias) => format!("RESULT · selected {alias} · PgUp/PgDn"),
        None => format!("PROVE RESULT · {} · PgUp/PgDn", card.outcome),
    }
}

pub(super) fn lines(
    model: &ProvePhaseModel,
    card: &PhaseResultCardModel,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = selected_context_lines(model, width, reading_next_step(card));
    lines.extend(ordered_rows(&card.detail_rows).into_iter().flat_map(|row| {
        row.text
            .split('\n')
            .map(|text| Line::styled(text.to_string(), theme::primary()))
    }));
    lines
}

fn selected_context_lines(
    model: &ProvePhaseModel,
    width: usize,
    next: &'static str,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(finding) = model.finding.as_ref() {
        let mut identity = compact_identity_line(model, finding, width.saturating_sub(9));
        identity
            .spans
            .insert(0, Span::styled("Selected ", theme::label()));
        let stale = model
            .proof
            .as_ref()
            .is_some_and(|proof| proof.requires_revalidation);
        lines.push(identity);
        lines.push(compact_status_line(finding, stale, width));
    }
    lines.push(Line::styled(next, theme::accent()));
    lines
}

fn reading_next_step(card: &PhaseResultCardModel) -> &'static str {
    use kuzushi_core::workflow_attempts::PhaseResultAction;
    if card.actions.contains(&PhaseResultAction::Select) {
        return "NEXT read result before selection";
    }
    "NEXT inspect result before retrying"
}

// Put the canonical result summary before its receipt. Keep every remaining
// row in order, including cost, omitted-ledger disclosures and source lineage.
fn ordered_rows(rows: &[PhaseResultDetailRow]) -> Vec<&PhaseResultDetailRow> {
    let summary = rows.iter().position(|row| {
        row.key
            .as_ref()
            .is_some_and(|key| key.role == RunCellRoleV1::ResultSummary)
    });
    summary
        .into_iter()
        .chain((0..rows.len()).filter(|index| Some(*index) != summary))
        .map(|index| &rows[index])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::run_lifecycle::{RunCellKey, RunCellSourceV1, RunItemId};

    fn detail(text: &str, role: Option<RunCellRoleV1>) -> PhaseResultDetailRow {
        PhaseResultDetailRow {
            key: role.map(|role| RunCellKey {
                source: RunCellSourceV1::Item(RunItemId::new()),
                role,
                ordinal: 0,
            }),
            disclosed_keys: Default::default(),
            text: text.into(),
        }
    }

    #[test]
    fn assessment_precedes_receipt_without_losing_evidence_or_cost() {
        let rows = vec![
            detail("cost unavailable", None),
            detail(
                "likely-exploitable (model assessment)",
                Some(RunCellRoleV1::ResultSummary),
            ),
            detail("runtime not attempted", Some(RunCellRoleV1::ResultSummary)),
            detail("source identity and final evidence", None),
        ];
        let ordered = ordered_rows(&rows);
        assert_eq!(ordered, vec![&rows[1], &rows[0], &rows[2], &rows[3]]);
    }

    #[test]
    fn unavailable_or_empty_result_retains_its_honest_order() {
        let rows = vec![
            detail("receipt unavailable", None),
            detail("open the failed run", None),
        ];
        assert_eq!(ordered_rows(&rows), vec![&rows[0], &rows[1]]);
        assert!(ordered_rows(&[]).is_empty());
    }

    fn result_card() -> PhaseResultCardModel {
        PhaseResultCardModel {
            attempt_id: "proof-attempt".into(),
            outcome: "completed".into(),
            emphasis: crate::PhaseResultEmphasis::DominantDecision,
            compact_summary: "Prove ready".into(),
            detail: String::new(),
            detail_rows: vec![
                detail("Provider cost is unavailable.", None),
                detail(
                    "Likely exploitable (model assessment); runtime not attempted.",
                    Some(RunCellRoleV1::ResultSummary),
                ),
                detail(
                    &"Full source evidence remains readable across wrapped rows. ".repeat(30),
                    None,
                ),
                detail("FINAL EVIDENCE · source identity retained", None),
            ],
            semantic_keys: Default::default(),
            actions: vec![kuzushi_core::workflow_attempts::PhaseResultAction::Select],
            control_hint: "u Use proof set · o Open".into(),
            recommended: "Review remains required".into(),
        }
    }

    fn result_body() -> crate::ui_view_models::PhaseCockpitBody {
        crate::ui_view_models::PhaseCockpitBody::Prove(ProvePhaseModel {
            pending_result: Some(result_card()),
            finding: None,
            attack_path: Default::default(),
            proof: None,
            selection_disclosure: None,
            empty_hint: None,
            investigation: None,
            trace: None,
            deferral: None,
        })
    }

    fn rendered_result(width: u16, height: u16, offset: u16, selected: Option<&str>) -> String {
        use ratatui::{backend::TestBackend, Terminal};
        let mut body = result_body();
        if let crate::ui_view_models::PhaseCockpitBody::Prove(model) = &mut body {
            model.finding = selected.map(|alias| FindingDetailModel {
                alias: Some(alias.to_string()),
                ..Default::default()
            });
        }
        let area = Rect::new(0, 0, width, height);
        let plan = crate::ui_view_models::phase_presentation_plan(
            &body,
            area,
            Some(PhaseSurfaceId::ProveEvidence),
            None,
            crate::ui_view_models::AttentionMode::ResultReady,
        );
        assert_eq!(plan.effective_focus, PhaseSurfaceId::ProveResult);
        assert_eq!(plan.surfaces.len(), 1);
        assert_eq!(plan.surfaces[0].rect, area);
        assert_eq!(
            plan.surfaces[0].interaction,
            crate::ui_view_models::SurfaceInteraction::Scrollable
        );
        let mut scroll = crate::app::WorkbenchSurfaceScroll::default();
        scroll.set(PhaseSurfaceId::ProveResult, offset);
        let state = PhaseRenderState {
            focus: Some(plan.effective_focus),
            surface: Some(plan.effective_focus),
            role: crate::ui_view_models::SurfaceRole::Standard,
            scroll: &scroll,
            density: plan.density,
        };
        let crate::ui_view_models::PhaseCockpitBody::Prove(model) = body else {
            unreachable!()
        };
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| super::super::render(frame, area, &model, state))
            .unwrap();
        let buffer = terminal.backend().buffer();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn short_result_reader_shows_assessment_then_scrolls_to_final_evidence() {
        for (width, height) in [(40, 6), (60, 12), (80, 16)] {
            let first = rendered_result(width, height, 0, None);
            assert!(first.contains("model assessment"), "{first}");
            assert!(!first.contains("FINAL EVIDENCE"), "{first}");
            let last = rendered_result(width, height, u16::MAX, None);
            assert!(last.contains("FINAL EVIDENCE"), "{last}");
            assert!(last.contains("PROVE RESULT"), "{last}");
        }
    }

    #[test]
    fn final_evidence_keeps_the_current_selection_labeled_in_the_title() {
        let last = rendered_result(40, 6, u16::MAX, Some("F-0007"));
        assert!(last.contains("selected F-0007"), "{last}");
        assert!(last.contains("FINAL EVIDENCE"), "{last}");
        assert!(last.contains("PgUp/PgDn"), "{last}");
    }
}
