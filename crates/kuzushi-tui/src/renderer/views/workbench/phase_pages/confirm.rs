use super::*;
use crate::ui_view_models::{
    FindingDetailModel, FindingEvidenceRow, InvestigationPlanModel, ProvePhaseModel,
    TraceEvidenceModel, TraceHopModel,
};
use ratatui::layout::{Constraint, Direction, Layout};

mod pending_result;
mod proof;
mod trace;

use proof::{
    compact_proof_lines, finding_header_lines, proof_ladder_lines, proof_lines, proof_title,
};

const SIDE_BY_SIDE_MIN_WIDTH: u16 = 78;

pub(super) fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ProvePhaseModel,
    state: PhaseRenderState,
) {
    if let Some(result) = model.pending_result.as_ref() {
        return pending_result::render(frame, area, model, result, state);
    }
    if let Some(plan) = model.investigation.as_ref() {
        return render_investigation_card(frame, area, plan, state);
    }
    render_prove_body(frame, area, model, state);
}

fn render_prove_body(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ProvePhaseModel,
    state: PhaseRenderState,
) {
    let Some(finding) = model.finding.as_ref() else {
        render_empty(frame, area, model, state);
        return;
    };
    if uses_critical_compact_status(area, state) {
        render_critical_compact(frame, area, model, finding, state);
        return;
    }
    match state.role {
        crate::ui_view_models::SurfaceRole::Canvas => {
            return render_unzoomed(frame, area, model, finding, state);
        }
        crate::ui_view_models::SurfaceRole::Drawer => {
            return render_next_action_menu(frame, area, finding, state);
        }
        crate::ui_view_models::SurfaceRole::Standard => {}
    }
    if let Some(pane) = state.surface {
        render_zoomed(frame, area, model, state, pane);
        return;
    }
    render_unzoomed(frame, area, model, finding, state);
}

/// The bounded investigation plan card: why, evidence goals, the safety
/// boundary radio (a real `verify:finding mode` choice), the stop conditions
/// that actually hold, and the exact command Enter drafts.
fn render_investigation_card(
    frame: &mut Frame<'_>,
    area: Rect,
    plan: &InvestigationPlanModel,
    state: PhaseRenderState,
) {
    let width = area.width.saturating_sub(2) as usize;
    let mut lines = investigation_lines(plan, width);
    if width < 60 {
        lines.remove(0);
    }
    render_lines_pane(
        frame,
        area,
        format!("{} · {}", plan.reference, investigation_status_title(plan)),
        lines,
        PhaseSurfaceId::ProveInvestigation,
        state,
    );
}

fn investigation_status_title(plan: &InvestigationPlanModel) -> &'static str {
    if plan.empirical
        && !plan
            .local_readiness
            .is_some_and(|readiness| readiness.can_attempt())
    {
        return "UNAVAILABLE";
    }
    "INVESTIGATE"
}

fn investigation_lines(plan: &InvestigationPlanModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled(
        fit(&format!("{} · {}", plan.reference, plan.severity), width),
        theme::heading(),
    )];
    append_backend_readiness(&mut lines, plan, width);
    append_model_ladder(&mut lines, plan, width);
    lines.push(Line::styled("SAFETY BOUNDARY", theme::label()));
    lines.extend(boundary_lines(plan.empirical, width));
    append_wrapped(&mut lines, &plan.why, width, theme::muted());
    lines.push(Line::styled("EVIDENCE GOALS", theme::label()));
    append_evidence_goals(&mut lines, plan, width);
    append_investigation_stop_conditions(&mut lines, width);
    append_wrapped(&mut lines, &plan.command, width, theme::accent());
    lines
}

fn append_wrapped(
    lines: &mut Vec<Line<'static>>,
    text: &str,
    width: usize,
    style: ratatui::style::Style,
) {
    lines.extend(
        wrap_text(text, width.max(1))
            .into_iter()
            .map(|row| Line::styled(row, style)),
    );
}

fn append_backend_readiness(
    lines: &mut Vec<Line<'static>>,
    plan: &InvestigationPlanModel,
    width: usize,
) {
    if !plan.empirical {
        return;
    }
    let message = plan
        .local_readiness
        .map(|readiness| readiness.message())
        .unwrap_or("Local reproduction availability has not been checked; reopen the card");
    append_wrapped(lines, message, width, theme::primary());
    append_wrapped(
        lines,
        "No model is used in this mode. Supported execution requires confirmation when submitted.",
        width,
        theme::muted(),
    );
}

fn append_evidence_goals(
    lines: &mut Vec<Line<'static>>,
    plan: &InvestigationPlanModel,
    width: usize,
) {
    for goal in &plan.evidence_goals {
        append_wrapped(lines, &format!("  ▸ {goal}"), width, theme::primary());
    }
}

fn append_model_ladder(
    lines: &mut Vec<Line<'static>>,
    plan: &InvestigationPlanModel,
    width: usize,
) {
    if plan.empirical {
        return;
    }
    if width >= 60 {
        lines.push(Line::styled("MODEL SETTINGS", theme::label()));
    }
    for rung in &plan.model_ladder {
        append_wrapped(lines, &format!("  · {rung}"), width, theme::muted());
    }
}

fn append_investigation_stop_conditions(lines: &mut Vec<Line<'static>>, width: usize) {
    lines.push(Line::styled("STOP CONDITIONS", theme::label()));
    append_wrapped(
        lines,
        "  · nothing runs until you submit the drafted command",
        width,
        theme::muted(),
    );
    append_wrapped(
        lines,
        "  · local reproduction requires a supported backend and explicit confirmation",
        width,
        theme::muted(),
    );
}

fn boundary_lines(empirical: bool, width: usize) -> Vec<Line<'static>> {
    let rows = [
        (
            !empirical,
            "Static-only (mode=model) — source analysis, no target or harness code executes",
        ),
        (
            empirical,
            "Local reproduction (mode=empirical) — attempt an isolated proof harness",
        ),
    ];
    let mut lines = Vec::new();
    for (selected, label) in rows {
        let marker = if selected { "(•)" } else { "( )" };
        append_wrapped(
            &mut lines,
            &format!("  {marker} {label}"),
            width,
            theme::primary(),
        );
    }
    lines
}

fn render_next_action_menu(
    frame: &mut Frame<'_>,
    area: Rect,
    finding: &FindingDetailModel,
    state: PhaseRenderState,
) {
    let width = area.width.saturating_sub(2) as usize;
    let lines = next_action_menu_lines(finding, width);
    render_lines_pane(
        frame,
        area,
        "CHOOSE NEXT ACTION",
        lines,
        PhaseSurfaceId::ProveNextAction,
        state,
    );
}

fn next_action_menu_lines(finding: &FindingDetailModel, width: usize) -> Vec<Line<'static>> {
    let reference = finding
        .alias
        .clone()
        .unwrap_or_else(|| finding.identity_label.clone());
    let mut lines = next_action_specs(&reference)
        .into_iter()
        .map(|(key, action, consequence)| {
            Line::from(vec![
                Span::styled(format!(" {key}  "), theme::accent()),
                Span::styled(format!("{action:<22}"), theme::primary()),
                Span::styled(fit(&consequence, width.saturating_sub(27)), theme::muted()),
            ])
        })
        .collect::<Vec<_>>();
    lines.push(Line::styled(
        fit("D defer proof · Esc return to findings", width),
        theme::muted(),
    ));
    lines
}

fn next_action_specs(reference: &str) -> [(&'static str, &'static str, String); 4] {
    [
        (
            "v",
            "Run investigation",
            format!("draft verify for {reference} — resolve missing evidence, attempt safe reproduction"),
        ),
        (
            "c",
            "Generate attack chain",
            "model prerequisites, trust transitions, and impact over verified findings".to_string(),
        ),
        (
            "5",
            "Draft patch",
            "open Fix with this finding to stage a remediation".to_string(),
        ),
        (
            "x",
            "Add suppression rule",
            "draft an expiring rule with an auditable reason".to_string(),
        ),
    ]
}

fn render_unzoomed(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ProvePhaseModel,
    finding: &FindingDetailModel,
    state: PhaseRenderState,
) {
    if area.width < 50 || area.height < 10 {
        render_critical_compact(frame, area, model, finding, state);
        return;
    }
    let status_rows = status_lines(model, finding, area.width.saturating_sub(2) as usize)
        .len()
        .saturating_add(2)
        .min(area.height.saturating_sub(4) as usize) as u16;
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(status_rows), Constraint::Min(4)])
        .split(area);
    render_status(frame, rows[0], model, finding, state);
    if area.width >= SIDE_BY_SIDE_MIN_WIDTH {
        render_reference_body(frame, rows[1], model, finding, state);
    } else {
        render_compact_body(frame, rows[1], model, finding, state);
    }
}

fn uses_critical_compact_status(area: Rect, state: PhaseRenderState) -> bool {
    matches!(
        state.density,
        LayoutDensity::Sparse | LayoutDensity::Focused | LayoutDensity::Guided
    ) && state.surface == Some(PhaseSurfaceId::ProveStatus)
        && (area.width < 50 || area.height < 10)
}

fn render_critical_compact(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ProvePhaseModel,
    finding: &FindingDetailModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        compact_status_title(state),
        critical_compact_lines(model, finding, area.width.saturating_sub(2) as usize),
        PhaseSurfaceId::ProveStatus,
        state,
    );
}

fn compact_status_title(state: PhaseRenderState) -> &'static str {
    if state.density == LayoutDensity::Focused {
        "ZOOM · PROVE STATUS / NEXT"
    } else {
        "PROVE · STATUS / NEXT"
    }
}

fn critical_compact_lines(
    model: &ProvePhaseModel,
    finding: &FindingDetailModel,
    width: usize,
) -> Vec<Line<'static>> {
    let stale = model
        .proof
        .as_ref()
        .is_some_and(|proof| proof.requires_revalidation);
    let mut lines = vec![
        compact_identity_line(model, finding, width),
        compact_status_line(finding, stale, width),
    ];
    lines.extend(proof_deferral_lines(model, width));
    lines.push(compact_next_line(finding, width));
    lines
}

fn compact_identity_line(
    model: &ProvePhaseModel,
    finding: &FindingDetailModel,
    width: usize,
) -> Line<'static> {
    let identity = finding.alias.as_deref().unwrap_or(&finding.identity_label);
    let label = model
        .selection_disclosure
        .as_ref()
        .map(|disclosure| format!("⚠ {}", disclosure.message))
        .unwrap_or_else(|| {
            format!(
                "{identity} {} {}src {} {}",
                finding.proof_meter,
                finding.source_count,
                compact_confidence(finding.proof_confidence_label.as_str()),
                finding.severity_label
            )
        });
    Line::styled(fit(&label, width), theme::heading())
}

fn compact_status_line(finding: &FindingDetailModel, stale: bool, width: usize) -> Line<'static> {
    let stale_label = if stale { " · ⚠ STALE" } else { "" };
    let status = format!(
        "{} · {}{stale_label}",
        finding.lifecycle_status, finding.proof_meter
    );
    Line::from(vec![
        Span::styled("STATUS ", theme::label()),
        Span::styled(
            fit(&status, width.saturating_sub(7)),
            if stale {
                theme::warn()
            } else {
                theme::primary()
            },
        ),
    ])
}

fn compact_next_line(finding: &FindingDetailModel, width: usize) -> Line<'static> {
    let next = finding
        .next_command
        .as_deref()
        .unwrap_or(finding.next_action_label.as_str());
    Line::from(vec![
        Span::styled("NEXT   ", theme::warn()),
        Span::styled(fit(next, width.saturating_sub(7)), theme::accent()),
    ])
}

fn compact_confidence(label: &str) -> &str {
    match label {
        "RUNTIME VERIFIED" | "CONFIRMED" => "runtime",
        "LIKELY" => "static",
        "DISMISSED" => "dismissed",
        _ => "signal",
    }
}

#[cfg(test)]
mod compact_confidence_tests {
    use super::compact_confidence;

    #[test]
    fn compact_proof_bands_use_plain_words() {
        assert_eq!(compact_confidence("RUNTIME VERIFIED"), "runtime");
        assert_eq!(compact_confidence("LIKELY"), "static");
        assert_eq!(compact_confidence("unverified"), "signal");
        assert_eq!(compact_confidence("DISMISSED"), "dismissed");
    }
}

pub(super) fn plain_lines(model: &ProvePhaseModel, width: usize) -> Vec<Line<'static>> {
    if let Some(result) = model.pending_result.as_ref() {
        return pending_result::lines(model, result, width);
    }
    let Some(finding) = model.finding.as_ref() else {
        return divider_lines("STATUS / NEXT", empty_selection_lines(model), width);
    };
    let mut lines = Vec::new();
    if let Some(trace) = model.trace.as_ref() {
        lines.extend(divider_lines("TRACE", trace::lines(trace), width));
    }
    if let Some(plan) = model.investigation.as_ref() {
        lines.extend(divider_lines(
            "INVESTIGATION PLAN",
            investigation_lines(plan, width),
            width,
        ));
    }
    lines.extend(divider_lines(
        "STATUS / NEXT",
        status_lines(model, finding, width),
        width,
    ));
    lines.extend(divider_lines(
        "EVIDENCE",
        evidence_lines(finding, width),
        width,
    ));
    append_plain_dataflow(&mut lines, finding, width);
    lines.extend(divider_lines(
        "PROOF LADDER",
        proof_ladder_lines(finding, model.proof.as_ref(), width),
        width,
    ));
    lines.extend(divider_lines(
        proof_title(model.proof.as_ref()),
        proof_lines(model.proof.as_ref(), finding, width),
        width,
    ));
    lines
}

fn append_plain_dataflow(
    lines: &mut Vec<Line<'static>>,
    finding: &FindingDetailModel,
    width: usize,
) {
    if finding.dataflow_evidence.is_empty() {
        return;
    }
    lines.extend(divider_lines(
        "AUDITED DATAFLOW",
        dataflow_lines(finding, width),
        width,
    ));
}

fn render_empty(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ProvePhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "STATUS / NEXT",
        empty_selection_lines(model),
        PhaseSurfaceId::ProveStatus,
        state,
    );
}

fn empty_selection_lines(model: &ProvePhaseModel) -> Vec<Line<'static>> {
    let review_key = crate::app::WorkbenchPage::Review.page_key().to_string();
    empty_state_panel(
        "no finding selected",
        &[model
            .empty_hint
            .as_deref()
            .unwrap_or("select a finding in Review")],
        &[(review_key.as_str(), "open Review and choose a finding")],
    )
}

fn render_status(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ProvePhaseModel,
    finding: &FindingDetailModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "STATUS / NEXT",
        status_lines(model, finding, area.width.saturating_sub(2) as usize),
        PhaseSurfaceId::ProveStatus,
        state,
    );
}

fn status_lines(
    model: &ProvePhaseModel,
    finding: &FindingDetailModel,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = selection_disclosure_lines(model.selection_disclosure.as_ref(), width);
    // The proof subject is a finding today; chain-shaped subjects arrive
    // with core chain validation, so the label states the artifact kind.
    lines.push(Line::styled(
        fit(
            &format!(
                "PROOF SUBJECT · finding {}",
                finding
                    .alias
                    .clone()
                    .unwrap_or_else(|| finding.identity_label.clone())
            ),
            width,
        ),
        theme::label(),
    ));
    lines.extend(finding_header_lines(finding, width));
    lines.extend(proof_deferral_lines(model, width));
    if model
        .proof
        .as_ref()
        .is_some_and(|proof| proof.requires_revalidation)
    {
        lines.push(Line::styled(
            fit("⚠ prior proof is stale for this observation", width),
            theme::warn(),
        ));
    }
    lines
}

/// The operator's recorded decision to postpone proof, disclosed above the
/// proof block. It reports a decision, not evidence: nothing here feeds the
/// proof ladder, the proof meter, or the confidence band.
fn proof_deferral_lines(model: &ProvePhaseModel, width: usize) -> Vec<Line<'static>> {
    let Some(deferral) = model.deferral.as_ref() else {
        return Vec::new();
    };
    vec![Line::styled(
        fit(&format!("⏸ {}", deferral.disclosure_line()), width),
        theme::warn(),
    )]
}

fn render_reference_body(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ProvePhaseModel,
    finding: &FindingDetailModel,
    state: PhaseRenderState,
) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(area);
    render_evidence(frame, columns[0], finding, state);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(columns[1]);
    render_ladder(frame, right[0], model, finding, state);
    render_runtime_proof(frame, right[1], model, finding, state);
}

fn render_compact_body(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ProvePhaseModel,
    finding: &FindingDetailModel,
    state: PhaseRenderState,
) {
    let width = area.width.saturating_sub(2) as usize;
    let mut lines = evidence_and_dataflow_lines(finding, area.width.saturating_sub(2));
    lines.push(divider("PROOF LADDER", area.width.saturating_sub(2)));
    lines.extend(proof_ladder_lines(finding, model.proof.as_ref(), width));
    lines.push(divider(
        proof_title(model.proof.as_ref()),
        area.width.saturating_sub(2),
    ));
    lines.extend(compact_proof_lines(model.proof.as_ref(), finding, width));
    render_lines_pane(
        frame,
        area,
        "EVIDENCE / PROOF · z attack path",
        lines,
        PhaseSurfaceId::ProveEvidence,
        state,
    );
}

fn render_zoomed(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ProvePhaseModel,
    state: PhaseRenderState,
    surface: PhaseSurfaceId,
) {
    let Some(finding) = model.finding.as_ref() else {
        render_empty(frame, area, model, state);
        return;
    };
    if surface == PhaseSurfaceId::ProveInvestigation {
        if let Some(plan) = model.investigation.as_ref() {
            return render_investigation_card(frame, area, plan, state);
        }
    }
    if surface == PhaseSurfaceId::ProveTrace {
        if let Some(trace) = model.trace.as_ref() {
            return trace::render(frame, area, trace, state);
        }
    }
    match surface {
        PhaseSurfaceId::ProveStatus => render_status(frame, area, model, finding, state),
        PhaseSurfaceId::ProveEvidence => render_evidence(frame, area, finding, state),
        PhaseSurfaceId::ProveLadder => render_ladder(frame, area, model, finding, state),
        PhaseSurfaceId::ProveReceipt => render_runtime_proof(frame, area, model, finding, state),
        _ => render_status(frame, area, model, finding, state),
    }
}

fn render_evidence(
    frame: &mut Frame<'_>,
    area: Rect,
    finding: &FindingDetailModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "EVIDENCE · z attack path",
        evidence_and_dataflow_lines(finding, area.width.saturating_sub(2)),
        PhaseSurfaceId::ProveEvidence,
        state,
    );
}

fn evidence_lines(finding: &FindingDetailModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![evidence_summary_line(finding, width)];
    if finding.evidence.is_empty() {
        lines.push(empty_evidence_line(width));
    }
    for (index, evidence) in finding.evidence.iter().enumerate() {
        lines.extend(evidence_anchor_lines(index, evidence, width));
    }
    if finding.evidence_overflow > 0 {
        lines.push(evidence_overflow_line(finding.evidence_overflow));
    }
    lines
}

/// EVIDENCE followed by the deep-auditor's AUDITED DATAFLOW section when the
/// finding carries dataflow rows. This is the frame-side parallel to the plain
/// projection's `append_plain_dataflow`, so the interactive Prove EVIDENCE pane
/// discloses the same falsifying dataflow the Review frame and plain output do.
fn evidence_and_dataflow_lines(
    finding: &FindingDetailModel,
    pane_width: u16,
) -> Vec<Line<'static>> {
    let width = pane_width as usize;
    let mut lines = evidence_lines(finding, width);
    if !finding.dataflow_evidence.is_empty() {
        lines.push(divider("AUDITED DATAFLOW", pane_width));
        lines.extend(dataflow_lines(finding, width));
    }
    lines
}

/// The deep-auditor's cited dataflow, rendered with the same anchor layout as
/// EVIDENCE. Only reached when at least one row exists, so no empty line.
fn dataflow_lines(finding: &FindingDetailModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for (index, row) in finding.dataflow_evidence.iter().enumerate() {
        let anchor = FindingEvidenceRow::from_dataflow(row);
        lines.extend(evidence_anchor_lines(index, &anchor, width));
    }
    if finding.dataflow_overflow > 0 {
        lines.push(evidence_overflow_line(finding.dataflow_overflow));
    }
    lines
}

fn evidence_summary_line(finding: &FindingDetailModel, width: usize) -> Line<'static> {
    let summary = format!(
        "{} · {} source(s) · {}",
        finding.evidence_state, finding.source_count, finding.corroboration
    );
    Line::styled(fit(&summary, width), theme::label())
}

fn empty_evidence_line(width: usize) -> Line<'static> {
    Line::styled(
        fit("no structured evidence anchors recorded", width),
        theme::muted(),
    )
}

fn evidence_anchor_lines(
    index: usize,
    evidence: &FindingEvidenceRow,
    width: usize,
) -> Vec<Line<'static>> {
    let header = format!("{}. {} · {}", index + 1, evidence.origin, evidence.header);
    let mut lines = vec![Line::styled(fit(&header, width), theme::primary())];
    if !evidence.snippet.trim().is_empty() {
        lines.push(Line::styled(fit(&evidence.snippet, width), theme::muted()));
    }
    if !evidence.rationale.trim().is_empty() {
        lines.push(Line::styled(
            fit(&evidence.rationale, width),
            theme::muted(),
        ));
    }
    lines
}

fn evidence_overflow_line(hidden: usize) -> Line<'static> {
    Line::styled(
        format!("… {hidden} more evidence anchor(s)"),
        theme::muted(),
    )
}

fn render_ladder(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ProvePhaseModel,
    finding: &FindingDetailModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "PROOF LADDER",
        proof_ladder_lines(
            finding,
            model.proof.as_ref(),
            area.width.saturating_sub(2) as usize,
        ),
        PhaseSurfaceId::ProveLadder,
        state,
    );
}

fn render_runtime_proof(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ProvePhaseModel,
    finding: &FindingDetailModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        proof_title(model.proof.as_ref()),
        proof_lines(
            model.proof.as_ref(),
            finding,
            area.width.saturating_sub(2) as usize,
        ),
        PhaseSurfaceId::ProveReceipt,
        state,
    );
}

#[cfg(test)]
mod investigation_card_tests {
    use super::*;

    fn plan(empirical: bool) -> InvestigationPlanModel {
        InvestigationPlanModel {
            reference: "F-7".to_string(),
            severity: "HIGH".to_string(),
            why: "evidence message-only".to_string(),
            evidence_goals: vec![
                "Recover structured evidence anchors (source and sink lines)".to_string(),
                "Attempt safe reproduction and record a runtime witness".to_string(),
            ],
            empirical,
            local_readiness: Some(kuzushi_core::verification::application::LocalVerificationReadiness::NoSupportedBackend),
            model_ladder: vec![
                "gate: not set (rejection only)".to_string(),
                "panel: workspace model x 1 pass(es)".to_string(),
            ],
            command: "run verify:finding {\"fingerprint\":\"abc\",\"mode\":\"model\"}".to_string(),
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
    fn card_states_goals_boundary_stop_conditions_and_the_exact_command() {
        let body = text(&investigation_lines(&plan(false), 100));
        assert!(body.contains("F-7 · HIGH"), "{body}");
        assert!(body.contains("EVIDENCE GOALS"), "{body}");
        assert!(
            body.contains("▸ Recover structured evidence anchors"),
            "{body}"
        );
        assert!(body.contains("(•) Static-only (mode=model)"), "{body}");
        assert!(
            body.contains("( ) Local reproduction (mode=empirical)"),
            "{body}"
        );
        assert!(
            body.contains("nothing runs until you submit the drafted command"),
            "{body}"
        );
        assert!(body.contains("run verify:finding {"), "{body}");
    }

    #[test]
    fn boundary_radio_follows_the_selected_mode() {
        let body = text(&investigation_lines(&plan(true), 100));
        assert!(
            body.contains("(•) Local reproduction (mode=empirical)"),
            "{body}"
        );
        assert!(body.contains("( ) Static-only (mode=model)"), "{body}");
    }

    #[test]
    fn local_mode_shows_the_missing_backend_without_a_model_ladder() {
        for width in [38, 78] {
            let lines = investigation_lines(&plan(true), width);
            let body = text(&lines);
            let joined = body.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(joined.contains("bubblewrap on Linux"), "{body}");
            assert!(joined.contains("No model is used"), "{body}");
            assert!(!body.contains("MODEL SETTINGS"), "{body}");
            assert!(lines.iter().all(|line| line.width() <= width), "{body}");
            assert!(joined.contains("explicit confirmation"), "{body}");
        }
    }

    #[test]
    fn card_discloses_the_configured_models() {
        let body = text(&investigation_lines(&plan(false), 100));
        assert!(body.contains("MODEL SETTINGS"), "{body}");
        assert!(body.contains("gate: not set (rejection only)"), "{body}");
        assert!(
            body.contains("panel: workspace model x 1 pass(es)"),
            "{body}"
        );
        // The ladder sits above the drafted command it summarizes.
        let ladder_at = body.find("MODEL SETTINGS").unwrap();
        let command_at = body.find("run verify:finding {").unwrap();
        assert!(ladder_at < command_at, "{body}");
    }
}

#[cfg(test)]
mod dataflow_prove_tests {
    use super::*;
    use crate::ui_view_models::TaintFlowPath;
    use kuzushi_core::findings::DataflowEvidenceRow;

    fn investigation() -> InvestigationPlanModel {
        InvestigationPlanModel {
            reference: "F-7".to_string(),
            severity: "HIGH".to_string(),
            why: "evidence message-only".to_string(),
            evidence_goals: vec!["Recover structured evidence anchors".to_string()],
            empirical: false,
            local_readiness: None,
            model_ladder: vec!["panel: workspace model x 1 pass(es)".to_string()],
            command: "run verify:finding {\"fingerprint\":\"abc\"}".to_string(),
        }
    }

    fn finding_with_dataflow() -> FindingDetailModel {
        FindingDetailModel {
            evidence_state: "evidence:0".to_string(),
            corroboration: "1".to_string(),
            dataflow_evidence: vec![DataflowEvidenceRow {
                origin: "deep auditor (cpg-rs path)".to_string(),
                location: "src/users.ts:91".to_string(),
                kind: "guard".to_string(),
                note: "falsifying evidence · authz gate".to_string(),
            }],
            dataflow_overflow: 0,
            ..FindingDetailModel::default()
        }
    }

    fn prove_model() -> ProvePhaseModel {
        ProvePhaseModel {
            pending_result: None,
            deferral: None,
            finding: Some(finding_with_dataflow()),
            attack_path: TaintFlowPath::default(),
            proof: None,
            selection_disclosure: None,
            empty_hint: None,
            investigation: Some(investigation()),
            trace: None,
        }
    }

    fn body(model: &ProvePhaseModel) -> String {
        plain_lines(model, 100)
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The AUDITED DATAFLOW section is additive: it renders after EVIDENCE
    /// without displacing the P1 MODEL SETTINGS block.
    #[test]
    fn prove_renders_audited_dataflow_and_keeps_the_model_ladder() {
        let text = body(&prove_model());

        assert!(text.contains("MODEL SETTINGS"), "{text}");
        assert!(text.contains("AUDITED DATAFLOW"), "{text}");
        assert!(text.contains("guard · src/users.ts:91"), "{text}");
        let evidence_at = text.find("EVIDENCE").unwrap();
        let dataflow_at = text.find("AUDITED DATAFLOW").unwrap();
        assert!(evidence_at < dataflow_at, "{text}");
    }

    /// Plain output and the compact STATUS/NEXT strip disclose the operator's
    /// deferral above the proof blocks; without one, nothing is claimed.
    #[test]
    fn prove_discloses_a_recorded_proof_deferral_above_the_proof_blocks() {
        let mut model = prove_model();
        model.deferral = Some(deferral_view());

        let text = body(&model);
        let disclosure_at = text
            .find("proof deferred by operator at generation scan-7")
            .unwrap_or_else(|| panic!("{text}"));
        assert!(
            disclosure_at < text.find("PROOF LADDER").unwrap(),
            "the decision is disclosed above the proof blocks: {text}"
        );
        assert!(
            text.contains("no runtime harness for this language yet"),
            "{text}"
        );

        let compact = compact_status_text(&model);
        assert!(compact.contains("proof deferred by operator"), "{compact}");
        assert!(
            !body(&prove_model()).contains("proof deferred"),
            "no deferral is ever implied without a recorded decision"
        );
    }

    fn deferral_view() -> kuzushi_core::workflow_attempts::ProofDeferralView {
        kuzushi_core::workflow_attempts::ProofDeferralView::from_record(
            &kuzushi_core::workflow_attempts::ProofDeferralRecorded::human(
                "semgrep:js/xss:9867ad7c",
                None,
                "scan-7",
                kuzushi_core::workflow_attempts::PhaseTargetSnapshot {
                    target: "/target".to_string(),
                    revision: Some("abc".to_string()),
                    dirty: false,
                },
                "no runtime harness for this language yet",
            ),
        )
    }

    fn compact_status_text(model: &ProvePhaseModel) -> String {
        critical_compact_lines(model, model.finding.as_ref().expect("finding"), 100)
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn prove_without_dataflow_rows_renders_no_dataflow_header() {
        let mut model = prove_model();
        model.finding = Some(FindingDetailModel::default());
        let text = body(&model);

        assert!(!text.contains("AUDITED DATAFLOW"), "{text}");
        assert!(text.contains("MODEL SETTINGS"), "{text}");
    }

    fn helper_text(finding: &FindingDetailModel) -> String {
        evidence_and_dataflow_lines(finding, 100)
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The frame-side EVIDENCE pane helper appends AUDITED DATAFLOW after the
    /// evidence summary, so the interactive frame discloses the same falsifying
    /// dataflow row the plain projection does.
    #[test]
    fn evidence_and_dataflow_helper_appends_audited_dataflow_after_evidence() {
        let text = helper_text(&finding_with_dataflow());

        let summary_at = text.find("evidence:0").expect("evidence summary present");
        let dataflow_at = text
            .find("AUDITED DATAFLOW")
            .expect("dataflow header present");
        assert!(summary_at < dataflow_at, "{text}");
        assert!(text.contains("guard · src/users.ts:91"), "{text}");
        assert!(text.contains("falsifying evidence"), "{text}");
    }

    #[test]
    fn evidence_and_dataflow_helper_omits_header_without_rows() {
        let text = helper_text(&FindingDetailModel::default());
        assert!(!text.contains("AUDITED DATAFLOW"), "{text}");
    }

    /// End-to-end frame smoke: rendering the Prove page at a side-by-side width
    /// paints AUDITED DATAFLOW into the EVIDENCE pane, not just the plain path.
    #[test]
    fn prove_frame_shows_audited_dataflow_in_evidence_pane() {
        use crate::app::WorkbenchSurfaceScroll;
        use ratatui::{backend::TestBackend, Terminal};

        let scroll = WorkbenchSurfaceScroll::default();
        let state = PhaseRenderState {
            focus: None,
            surface: None,
            role: SurfaceRole::Standard,
            scroll: &scroll,
            density: LayoutDensity::Dense,
        };
        let mut model = prove_model();
        model.investigation = None;

        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                render(frame, area, &model, state);
            })
            .unwrap();

        let rendered = format!("{:?}", terminal.backend().buffer());
        assert!(rendered.contains("AUDITED DATAFLOW"), "{rendered}");
    }
}

#[cfg(test)]
mod trace_screen_tests {
    use super::*;

    fn hop(label: &str, location: &str, annotation: &str) -> TraceHopModel {
        TraceHopModel {
            label: label.to_string(),
            location: location.to_string(),
            annotation: annotation.to_string(),
        }
    }

    fn trace_model() -> TraceEvidenceModel {
        TraceEvidenceModel {
            last_outcome: None,
            reference: "F-2".to_string(),
            severity: "HIGH".to_string(),
            identity: Some("target demo@1a2b3c4d · threat model @9f8e7d6c".to_string()),
            original: vec![hop("source", "src/input.rs:4", "attacker-controlled read")],
            expanded: vec![hop(
                "parse_header",
                "src/parse.rs:32",
                "length copied without bound",
            )],
            open_questions: vec!["is the header attacker-controlled over TLS?".to_string()],
            evidence_deltas: vec!["length reaches memcpy unchecked".to_string()],
            expand_command: "run trace:expand {\"fingerprint\":\"abc\"}".to_string(),
            next_hint: "resolve the open questions below".to_string(),
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
    fn trace_screen_separates_recorded_and_operator_requested_paths() {
        let body = text(&trace::lines(&trace_model()));
        assert!(
            body.contains("F-2 · HIGH · where does this value travel"),
            "{body}"
        );
        assert!(
            body.contains("target demo@1a2b3c4d · threat model @9f8e7d6c"),
            "{body}"
        );
        assert!(body.contains("RECORDED PATH"), "{body}");
        assert!(body.contains("▾ source — src/input.rs:4"), "{body}");
        assert!(
            body.contains("RECORDED EXPANSIONS · requested by operator"),
            "{body}"
        );
        assert!(body.contains("▾ parse_header — src/parse.rs:32"), "{body}");
        assert!(body.contains("length copied without bound"), "{body}");
        assert!(
            body.contains("? open: is the header attacker-controlled over TLS?"),
            "{body}"
        );
        assert!(body.contains("NEW EVIDENCE"), "{body}");
        assert!(body.contains("+ length reaches memcpy unchecked"), "{body}");
        assert!(body.contains("NEXT · resolve the open questions"), "{body}");
        assert!(body.contains("run trace:expand {"), "{body}");
    }

    #[test]
    fn empty_paths_render_honest_guidance_instead_of_invented_hops() {
        let mut model = trace_model();
        model.original.clear();
        model.expanded.clear();
        model.open_questions.clear();
        model.evidence_deltas.clear();
        model.next_hint = "no operator-requested hops yet".to_string();
        let body = text(&trace::lines(&model));
        assert!(
            body.contains("no located evidence anchors recorded"),
            "{body}"
        );
        assert!(body.contains("no operator-requested hops yet"), "{body}");
        assert!(!body.contains("NEW EVIDENCE"), "{body}");
    }
}
