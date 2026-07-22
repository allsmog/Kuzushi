use super::*;
use crate::ui_view_models::{
    FindingDetailModel, FindingEvidenceRow, InvestigationPlanModel, ProvePhaseModel,
    TraceEvidenceModel, TraceHopModel,
};
use ratatui::layout::{Constraint, Direction, Layout};

mod proof;

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
    render_lines_pane(
        frame,
        area,
        "INVESTIGATE · Enter draft command · m boundary · v cancel",
        investigation_lines(plan, area.width.saturating_sub(2) as usize),
        PhaseSurfaceId::ProveInvestigation,
        state,
    );
}

fn investigation_lines(plan: &InvestigationPlanModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::styled(
            fit(&format!("{} · {}", plan.reference, plan.severity), width),
            theme::heading(),
        ),
        Line::styled(fit(&plan.why, width), theme::muted()),
        Line::styled(fit("EVIDENCE GOALS", width), theme::label()),
    ];
    for goal in &plan.evidence_goals {
        lines.push(Line::styled(
            fit(&format!("  ▸ {goal}"), width),
            theme::primary(),
        ));
    }
    lines.push(Line::styled(fit("SAFETY BOUNDARY", width), theme::label()));
    lines.extend(boundary_lines(plan.empirical, width));
    lines.push(Line::styled(fit("STOP CONDITIONS", width), theme::label()));
    lines.push(Line::styled(
        fit(
            "  · nothing runs until you submit the drafted command",
            width,
        ),
        theme::muted(),
    ));
    lines.push(Line::styled(
        fit(
            "  · destructive shell drafts require explicit confirmation",
            width,
        ),
        theme::muted(),
    ));
    lines.push(Line::styled(fit(&plan.command, width), theme::accent()));
    lines
}

/// The Trace screen: the recorded path beside the operator-requested
/// expansion, every hop cited to file:line, open questions as first-class
/// `?` rows, and the evidence the last expansion added.
fn render_trace_screen(
    frame: &mut Frame<'_>,
    area: Rect,
    trace: &TraceEvidenceModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "TRACE · Enter draft trace:expand · v investigate · t close",
        trace_lines(trace, area.width.saturating_sub(2) as usize),
        PhaseSurfaceId::ProveTrace,
        state,
    );
}

fn trace_lines(trace: &TraceEvidenceModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled(
        fit(
            &format!(
                "{} · {} · where does this value travel",
                trace.reference, trace.severity
            ),
            width,
        ),
        theme::heading(),
    )];
    if let Some(identity) = trace.identity.as_ref() {
        lines.push(Line::styled(fit(identity, width), theme::muted()));
    }
    lines.push(Line::styled(fit("RECORDED PATH", width), theme::label()));
    if trace.original.is_empty() {
        lines.push(Line::styled(
            fit(
                "  no located evidence anchors recorded for this finding",
                width,
            ),
            theme::muted(),
        ));
    }
    for hop in &trace.original {
        lines.extend(trace_hop_lines(hop, width));
    }
    lines.push(Line::styled(
        fit("EXPANDED PATH · requested by operator", width),
        theme::label(),
    ));
    if trace.expanded.is_empty() {
        lines.push(Line::styled(
            fit(
                "  no operator-requested hops yet — the durable evidence store has none for this finding",
                width,
            ),
            theme::muted(),
        ));
    }
    for hop in &trace.expanded {
        lines.extend(trace_hop_lines(hop, width));
    }
    for question in &trace.open_questions {
        lines.push(Line::styled(
            fit(&format!("  ? open: {question}"), width),
            theme::warn(),
        ));
    }
    if !trace.evidence_deltas.is_empty() {
        lines.push(Line::styled(fit("NEW EVIDENCE", width), theme::label()));
        for delta in &trace.evidence_deltas {
            lines.push(Line::styled(
                fit(&format!("  + {delta}"), width),
                theme::primary(),
            ));
        }
    }
    lines.push(Line::styled(
        fit(&format!("NEXT · {}", trace.next_hint), width),
        theme::muted(),
    ));
    lines.push(Line::styled(
        fit(&trace.expand_command, width),
        theme::accent(),
    ));
    lines
}

fn trace_hop_lines(hop: &TraceHopModel, width: usize) -> Vec<Line<'static>> {
    let location = if hop.location.is_empty() {
        "location unrecorded".to_string()
    } else {
        hop.location.clone()
    };
    let mut lines = vec![Line::styled(
        fit(&format!("  ▾ {} — {}", hop.label, location), width),
        theme::primary(),
    )];
    if !hop.annotation.is_empty() {
        lines.push(Line::styled(
            fit(&format!("      {}", hop.annotation), width),
            theme::muted(),
        ));
    }
    lines
}

fn boundary_lines(empirical: bool, width: usize) -> Vec<Line<'static>> {
    let rows = [
        (
            !empirical,
            "Static-only (mode=model) — adversarial analysis, no code executes",
        ),
        (
            empirical,
            "Local reproduction (mode=empirical) — sandboxed PoC execution here",
        ),
    ];
    rows.into_iter()
        .map(|(selected, label)| {
            let marker = if selected { "(•)" } else { "( )" };
            Line::styled(
                fit(&format!("  {marker} {label}"), width),
                if selected {
                    theme::primary()
                } else {
                    theme::muted()
                },
            )
        })
        .collect()
}

/// The Choose-Next-Action menu: every row is an existing Prove hotkey with
/// its one-line consequence, so the operator authorizes the next move instead
/// of the agent silently picking one.
fn render_next_action_menu(
    frame: &mut Frame<'_>,
    area: Rect,
    finding: &FindingDetailModel,
    state: PhaseRenderState,
) {
    let width = area.width.saturating_sub(2) as usize;
    let reference = finding
        .alias
        .clone()
        .unwrap_or_else(|| finding.identity_label.clone());
    let rows: [(&str, &str, String); 4] = [
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
            "Mark false positive",
            "draft suppress — records a durable review decision with a reason".to_string(),
        ),
    ];
    let mut lines = Vec::new();
    for (key, action, consequence) in rows {
        lines.push(Line::from(vec![
            Span::styled(format!(" {key}  "), theme::accent()),
            Span::styled(format!("{action:<22}"), theme::primary()),
            Span::styled(fit(&consequence, width.saturating_sub(27)), theme::muted()),
        ]));
    }
    lines.push(Line::styled(
        fit("D defer proof · Esc return to findings", width),
        theme::muted(),
    ));
    render_lines_pane(
        frame,
        area,
        "CHOOSE NEXT ACTION",
        lines,
        PhaseSurfaceId::ProveNextAction,
        state,
    );
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
    vec![
        compact_identity_line(model, finding, width),
        compact_status_line(finding, stale, width),
        compact_next_line(finding, width),
    ]
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
        "CONFIRMED" => "CFM",
        "LIKELY" => "LIK",
        "DISMISSED" => "DIS",
        _ => "UNV",
    }
}

pub(super) fn plain_lines(model: &ProvePhaseModel, width: usize) -> Vec<Line<'static>> {
    let Some(finding) = model.finding.as_ref() else {
        return divider_lines("STATUS / NEXT", empty_selection_lines(model), width);
    };
    let mut lines = Vec::new();
    if let Some(trace) = model.trace.as_ref() {
        lines.extend(divider_lines("TRACE", trace_lines(trace, width), width));
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
    empty_state_panel(
        "no finding selected",
        &[model.empty_hint.unwrap_or("select a finding in Review")],
        &[("2", "open Review and choose a finding")],
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
    let mut lines = evidence_lines(finding, width);
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
            return render_trace_screen(frame, area, trace, state);
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
        evidence_lines(finding, area.width.saturating_sub(2) as usize),
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
        let body = text(&trace_lines(&trace_model(), 100));
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
            body.contains("EXPANDED PATH · requested by operator"),
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
        let body = text(&trace_lines(&model, 100));
        assert!(
            body.contains("no located evidence anchors recorded"),
            "{body}"
        );
        assert!(body.contains("no operator-requested hops yet"), "{body}");
        assert!(!body.contains("NEW EVIDENCE"), "{body}");
    }
}
