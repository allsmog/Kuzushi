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
    if model.chains.is_some() {
        lines.extend(divider_lines(
            "ATTACK CHAINS",
            chain_artifact_lines(model.chains.as_ref(), width),
            width,
        ));
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
        PhaseSurfaceId::ReviewChains => render_chain_artifacts(frame, area, model, state),
        _ => render_review_list(frame, area, model, state),
    }
}

/// The Attack Chains screen: chains as first-class artifacts over the SET of
/// confirmed findings — constituent references, assumption-labeled
/// prerequisites as side nodes, and the triage mutation each chain implies.
fn render_chain_artifacts(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ReviewPhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "ATTACK CHAINS · Enter open constituent · C close",
        chain_artifact_lines(model.chains.as_ref(), area.width.saturating_sub(2) as usize),
        PhaseSurfaceId::ReviewChains,
        state,
    );
}

fn chain_artifact_lines(
    chains: Option<&crate::ui_view_models::ChainArtifactsModel>,
    width: usize,
) -> Vec<Line<'static>> {
    let Some(chains) = chains else {
        return Vec::new();
    };
    if chains.candidates.is_empty() && chains.grounded.is_empty() {
        // The zero state is a statement about the confirmed set, not a
        // shrug: it names how many confirmed findings were folded and why
        // no scenario composed.
        let mut lines = vec![Line::styled(
            fit(
                &format!(
                    "no chain artifacts · {} confirmed finding(s) compose no entry→impact pair",
                    chains.confirmed_count
                ),
                width,
            ),
            theme::muted(),
        )];
        lines.extend(empty_state_panel(
            "no chain artifacts yet",
            &[
                "chains compose over CONFIRMED findings with entry- and impact-class roles",
                "confirm findings in Review, then run `run exploit-chain:scan {}` for grounded chains",
            ],
            &[("C", "close attack chains")],
        ));
        return lines;
    }
    let mut lines = vec![Line::styled(
        fit(
            &format!(
                "composed over {} confirmed finding(s) · deterministic fold seeds, exploit-chain:scan grounds",
                chains.confirmed_count
            ),
            width,
        ),
        theme::muted(),
    )];
    if let Some(identity) = chains.identity.as_ref() {
        lines.push(Line::styled(fit(identity, width), theme::muted()));
    }
    for (index, candidate) in chains.candidates.iter().enumerate() {
        lines.extend(candidate_lines(index, candidate, width));
    }
    for grounded in &chains.grounded {
        lines.extend(grounded_chain_lines(grounded, width));
    }
    lines
}

fn candidate_lines(
    index: usize,
    candidate: &crate::ui_view_models::ChainCandidateModel,
    width: usize,
) -> Vec<Line<'static>> {
    let constituents = candidate
        .links
        .iter()
        .map(|link| link.reference.as_str())
        .collect::<Vec<_>>()
        .join(" + ");
    let mut lines = vec![Line::styled(
        fit(
            &format!(
                "CANDIDATE {} · {} = {}",
                index + 1,
                candidate.surface,
                constituents
            ),
            width,
        ),
        theme::heading(),
    )];
    for link in &candidate.links {
        lines.push(Line::styled(
            fit(
                &format!(
                    "  {} {} [{}] {} · {}",
                    role_glyph(&link.role),
                    link.reference,
                    link.severity,
                    link.title,
                    link.file
                ),
                width,
            ),
            theme::primary(),
        ));
    }
    lines.push(Line::styled(
        fit(&format!("  {}", candidate.rationale), width),
        theme::muted(),
    ));
    if let Some(note) = candidate.mutation_note.as_deref() {
        lines.push(Line::styled(
            fit(&format!("  ⚠ {note}"), width),
            theme::warn(),
        ));
    }
    lines
}

fn grounded_chain_lines(
    chain: &crate::app::ExploitChainDetail,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled(
        fit(
            &format!(
                "GROUNDED {} · {:?} · {}",
                chain.id, chain.severity, chain.title
            ),
            width,
        ),
        theme::heading(),
    )];
    for step in &chain.steps {
        lines.push(Line::styled(
            fit(
                &format!(
                    "  ▸ {} — {} · {}:{}",
                    step.role, step.description, step.file, step.line
                ),
                width,
            ),
            theme::primary(),
        ));
    }
    for precondition in &chain.preconditions {
        lines.push(Line::styled(
            fit(&format!("  ? assumes: {precondition}"), width),
            theme::warn(),
        ));
    }
    if let Some(impact) = chain.impact_description.as_deref() {
        lines.push(Line::styled(
            fit(&format!("  impact: {impact}"), width),
            theme::muted(),
        ));
    }
    lines
}

fn role_glyph(role: &str) -> &'static str {
    match role {
        "entry" => "→",
        "pivot" => "↝",
        _ => "☒",
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

#[cfg(test)]
mod chain_artifact_tests {
    use super::*;
    use crate::ui_view_models::{ChainArtifactsModel, ChainCandidateModel, ChainLinkModel};

    fn candidate() -> ChainCandidateModel {
        let link = |role: &str, reference: &str, severity: &str| ChainLinkModel {
            role: role.to_string(),
            reference: reference.to_string(),
            severity: severity.to_string(),
            title: format!("{role} finding"),
            file: "src/net/handler.rs".to_string(),
        };
        ChainCandidateModel {
            surface: "src/net".to_string(),
            links: vec![
                link("entry", "F-1", "medium"),
                link("impact", "F-3", "high"),
            ],
            rationale: "entry reaches impact on one surface".to_string(),
            mutation_note: Some(
                "chain would raise F-1 toward the composed impact (advisory)".to_string(),
            ),
            open_command: "open F-1".to_string(),
        }
    }

    fn text(lines: &[Line<'static>]) -> String {
        lines
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn chain_screen_names_constituents_and_the_advisory_triage_mutation() {
        let chains = ChainArtifactsModel {
            identity: None,
            confirmed_count: 2,
            candidates: vec![candidate()],
            grounded: Vec::new(),
        };
        let body = text(&chain_artifact_lines(Some(&chains), 120));
        assert!(body.contains("F-1 + F-3"), "{body}");
        assert!(body.contains("[medium]"), "{body}");
        assert!(body.contains("⚠ chain would raise F-1"), "{body}");
        assert!(body.contains("2 confirmed finding(s)"), "{body}");
    }

    #[test]
    fn grounded_chains_render_assumptions_as_side_nodes() {
        let chains = ChainArtifactsModel {
            identity: None,
            confirmed_count: 0,
            candidates: Vec::new(),
            grounded: vec![crate::app::ExploitChainDetail {
                id: "AC-1".to_string(),
                title: "bucket tamper to heap write".to_string(),
                severity: crate::app::ChainSeverity::Critical,
                narrative: None,
                impact_description: Some("arbitrary heap write".to_string()),
                preconditions: vec!["attacker controls bucket contents".to_string()],
                steps: Vec::new(),
            }],
        };
        let body = text(&chain_artifact_lines(Some(&chains), 120));
        assert!(body.contains("GROUNDED AC-1"), "{body}");
        assert!(
            body.contains("? assumes: attacker controls bucket contents"),
            "{body}"
        );
        assert!(body.contains("impact: arbitrary heap write"), "{body}");
    }

    #[test]
    fn empty_chain_screen_explains_how_artifacts_come_to_exist() {
        let chains = ChainArtifactsModel {
            identity: None,
            confirmed_count: 0,
            candidates: Vec::new(),
            grounded: Vec::new(),
        };
        let body = text(&chain_artifact_lines(Some(&chains), 120));
        assert!(body.contains("no chain artifacts yet"), "{body}");
        assert!(body.contains("CONFIRMED findings"), "{body}");
    }
}
